"""For collating the results from parsing cvdump.exe into a more directly useful format."""

from pathlib import PureWindowsPath
from reccmp.isledecomp.types import EntityType
from .demangler import demangle_string_const, demangle_vtable
from .parser import CvdumpParser, LineValue, NodeKey
from .symbols import SymbolsEntry
from .types import CvdumpKeyError, CvdumpIntegrityError, TypeInfo


class CvdumpNode:
    # pylint: disable=too-many-instance-attributes
    # These two are required and allow us to identify the symbol
    section: int
    offset: int
    # aka the mangled name from the PUBLICS section
    decorated_name: str | None = None
    # optional "nicer" name (e.g. of a function from SYMBOLS section)
    friendly_name: str | None = None
    # To be determined by context after inserting data, unless the decorated
    # name makes this obvious. (i.e. string constants or vtables)
    # We choose not to assume that section 1 (probably ".text") contains only
    # functions. Smacker functions are linked to their own section "_UNSTEXT"
    node_type: EntityType | None = None
    # Function size can be read from the LINES section so use this over any
    # other value if we have it.
    # TYPES section can tell us the size of structs and other complex types.
    confirmed_size: int | None = None
    # Estimated by reading the distance between this symbol and the one that
    # follows in the same section.
    # If this is the last symbol in the section, we cannot estimate a size.
    estimated_size: int | None = None
    # Size as reported by SECTION CONTRIBUTIONS section. Not guaranteed to be
    # accurate.
    section_contribution: int | None = None
    addr: int | None = None
    symbol_entry: SymbolsEntry | None = None
    # Preliminary - only used for non-static variables at the moment
    data_type: TypeInfo | None = None

    def __init__(self, section: int, offset: int) -> None:
        self.section = section
        self.offset = offset

    def set_decorated(self, name: str):
        self.decorated_name = name

        if self.decorated_name.startswith("??_7"):
            self.node_type = EntityType.VTABLE
            self.friendly_name = demangle_vtable(self.decorated_name)

        elif self.decorated_name.startswith("??_8"):
            # This is the `vbtable' symbol for virtual inheritance.
            # Should be okay to reuse demangle_vtable. We still want to
            # remove things like "const" from the output.
            self.node_type = EntityType.DATA
            self.friendly_name = demangle_vtable(self.decorated_name)

        elif self.decorated_name.startswith("??_C@"):
            self.node_type = EntityType.STRING
            demangled = demangle_string_const(self.decorated_name)
            assert demangled is not None
            self.confirmed_size = demangled.len

        elif not self.decorated_name.startswith("?") and "@" in self.decorated_name:
            # C mangled symbol. The trailing at-sign with number tells the number of bytes
            # in the parameter list for __stdcall, __fastcall, or __vectorcall
            # For __cdecl it is more ambiguous and we would have to know which section we are in.
            # https://learn.microsoft.com/en-us/cpp/build/reference/decorated-names?view=msvc-170#FormatC
            self.node_type = EntityType.FUNCTION

    def name(self) -> str | None:
        """Prefer "friendly" name if we have it.
        This is what we have been using to match functions."""
        return (
            self.friendly_name
            if self.friendly_name is not None
            else self.decorated_name
        )

    def size(self) -> int | None:
        if self.confirmed_size is not None:
            return self.confirmed_size

        # Better to undershoot the size because we can identify a comparison gap easily
        if self.estimated_size is not None and self.section_contribution is not None:
            return min(self.estimated_size, self.section_contribution)

        # Return whichever one we have, or neither
        return self.estimated_size or self.section_contribution


class CvdumpAnalysis:
    """Collects the results from CvdumpParser into a list of nodes (i.e. symbols).
    These can then be analyzed by a downstream tool."""

    lines: dict[PureWindowsPath, list[LineValue]]

    def __init__(self, parser: CvdumpParser):
        """Read in as much information as we have from the parser.
        The more sections we have, the better our information will be."""
        node_dict: dict[NodeKey, CvdumpNode] = {}

        # PUBLICS is our roadmap for everything that follows.
        for pub in parser.publics:
            key = NodeKey(pub.section, pub.offset)
            if key not in node_dict:
                node_dict[key] = CvdumpNode(*key)

            node_dict[key].set_decorated(pub.name)

        for sizeref in parser.sizerefs:
            key = NodeKey(sizeref.section, sizeref.offset)
            if key not in node_dict:
                node_dict[key] = CvdumpNode(*key)

            node_dict[key].section_contribution = sizeref.size

        for glo in parser.globals:
            key = NodeKey(glo.section, glo.offset)
            if key not in node_dict:
                node_dict[key] = CvdumpNode(*key)

            node_dict[key].node_type = EntityType.DATA
            node_dict[key].friendly_name = glo.name

            try:
                # Check our types database for type information.
                # If we did not parse the TYPES section, we can only
                # get information for built-in "T_" types.
                g_info = parser.types.get(glo.type)
                node_dict[key].confirmed_size = g_info.size
                node_dict[key].data_type = g_info
                # Previously we set the symbol type to POINTER here if
                # the variable was known to be a pointer. We can derive this
                # information later when it's time to compare the variable,
                # so let's set these to symbol type DATA instead.
                # POINTER will be reserved for non-variable pointer data.
                # e.g. thunks, unwind section.
            except (CvdumpKeyError, CvdumpIntegrityError):
                # No big deal if we don't have complete type information.
                pass

        self.lines = parser.lines

        for sym in parser.symbols:
            key = NodeKey(sym.section, sym.offset)
            if key not in node_dict:
                node_dict[key] = CvdumpNode(*key)

            if sym.type == "S_GPROC32":
                node_dict[key].friendly_name = sym.name
                node_dict[key].confirmed_size = sym.size
                node_dict[key].node_type = EntityType.FUNCTION
                node_dict[key].symbol_entry = sym

                # Iterate through static variables defined in this function
                # generate decorated name "<variable name>___<func name>"
                for v in sym.static_variables:
                    key = NodeKey(v.section, v.offset)
                    if key not in node_dict:
                        node_dict[key] = CvdumpNode(*key)
                    node_dict[key].node_type = EntityType.DATA
                    # TODO this format is required for `match_msvc::match_static_variables` to find the variable
                    # Look at either documenting this dependency or reworking the query
                    node_dict[key].decorated_name = f"{v.name}___{sym.name}"
                    node_dict[key].friendly_name = v.name
                    try:
                        v_info = parser.types.get(v.type)
                        node_dict[key].confirmed_size = v_info.size
                        node_dict[key].data_type = v_info
                    except (CvdumpKeyError, CvdumpIntegrityError):
                        # No big deal if we don't have complete type information.
                        pass

        self.nodes: list[CvdumpNode] = [
            v for _, v in dict(sorted(node_dict.items())).items()
        ]
        self._estimate_size()

    def _estimate_size(self):
        """Get the distance between one section:offset value and the next one
        in the same section. This gives a rough estimate of the size of the symbol.
        If we have information from SECTION CONTRIBUTIONS, take whichever one is
        less to get the best approximate size."""
        for i in range(len(self.nodes) - 1):
            this_node = self.nodes[i]
            next_node = self.nodes[i + 1]

            # If they are in different sections, we can't compare them
            if this_node.section != next_node.section:
                continue

            this_node.estimated_size = next_node.offset - this_node.offset
