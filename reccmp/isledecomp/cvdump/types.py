from dataclasses import dataclass
import re
import logging
from typing import Any, NamedTuple


logger = logging.getLogger(__name__)


class CvdumpTypeError(Exception):
    pass


class CvdumpKeyError(KeyError):
    pass


class CvdumpIntegrityError(Exception):
    pass


class FieldListItem(NamedTuple):
    """Member of a class or structure"""

    offset: int
    name: str
    type: str


@dataclass
class VirtualBaseClass:
    type: str
    index: int
    direct: bool


@dataclass
class VirtualBasePointer:
    vboffset: int
    bases: list[VirtualBaseClass]


class ScalarType(NamedTuple):
    offset: int
    name: str | None
    type: str

    @property
    def size(self) -> int:
        return scalar_type_size(self.type)

    @property
    def format_char(self) -> str:
        return scalar_type_format_char(self.type)

    @property
    def is_pointer(self) -> bool:
        return scalar_type_pointer(self.type)


class TypeInfo(NamedTuple):
    key: str
    size: int | None
    name: str | None = None
    members: list[FieldListItem] | None = None

    def is_scalar(self) -> bool:
        # TODO: distinction between a class with zero members and no vtable?
        return self.members is None


def normalize_type_id(key: str) -> str:
    """Helper for TYPES parsing to ensure a consistent format.
    If key begins with "T_" it is a built-in type.
    Else it is a hex string. We prefer lower case letters and
    no leading zeroes. (UDT identifier pads to 8 characters.)"""
    if key[0] == "0":
        return f"0x{key[-4:].lower()}"

    # Remove numeric value for "T_" type. We don't use this.
    return key.partition("(")[0]


def scalar_type_pointer(type_name: str) -> bool:
    return type_name.startswith("T_32P")


def scalar_type_size(type_name: str) -> int:
    if scalar_type_pointer(type_name):
        return 4

    if "CHAR" in type_name:
        return 2 if "WCHAR" in type_name else 1

    if "SHORT" in type_name:
        return 2

    if "QUAD" in type_name or "64" in type_name:
        return 8

    return 4


def scalar_type_signed(type_name: str) -> bool:
    if scalar_type_pointer(type_name):
        return False

    # According to cvinfo.h, T_WCHAR is unsigned
    return not type_name.startswith("T_U") and not type_name.startswith("T_W")


def scalar_type_format_char(type_name: str) -> str:
    if scalar_type_pointer(type_name):
        return "L"

    # "Really a char"
    if type_name.startswith("T_RCHAR"):
        return "c"

    # floats
    if type_name.startswith("T_REAL"):
        return "d" if "64" in type_name else "f"

    size = scalar_type_size(type_name)
    char = ({1: "b", 2: "h", 4: "l", 8: "q"}).get(size, "l")

    return char if scalar_type_signed(type_name) else char.upper()


def member_list_to_struct_string(members: list[ScalarType]) -> str:
    """Create a string for use with struct.unpack"""

    format_string = "".join(m.format_char for m in members)
    if len(format_string) > 0:
        return "<" + format_string

    return ""


def join_member_names(parent: str, child: str | None) -> str:
    """Helper method to combine parent/child member names.
    Child member name is None if the child is a scalar type."""

    if child is None:
        return parent

    # If the child is an array index, join without the dot
    if child.startswith("["):
        return f"{parent}{child}"

    return f"{parent}.{child}"


class CvdumpTypesParser:
    """Parser for cvdump output, TYPES section.
    Tricky enough that it demands its own parser."""

    # Marks the start of a new type
    INDEX_RE = re.compile(r"(?P<key>0x\w+) : .* (?P<type>LF_\w+)")

    # LF_FIELDLIST class/struct member
    LIST_RE = re.compile(
        r"list\[\d+\] = LF_MEMBER, (?P<scope>\w+), type = (?P<type>[^,]*), offset = (?P<offset>\d+)\s+member name = '(?P<name>[^']*)'"
    )

    # LF_FIELDLIST vtable indicator
    VTABLE_RE = re.compile(r"list\[\d+\] = LF_VFUNCTAB")

    # LF_FIELDLIST superclass indicator
    SUPERCLASS_RE = re.compile(
        r"list\[\d+\] = LF_BCLASS, (?P<scope>\w+), type = (?P<type>.*), offset = (?P<offset>\d+)"
    )

    # LF_FIELDLIST virtual direct/indirect base pointer
    VBCLASS_RE = re.compile(
        r"list\[\d+\] = LF_(?P<indirect>I?)VBCLASS, .* base type = (?P<type>.*)\n\s+virtual base ptr = .+, vbpoff = (?P<vboffset>\d+), vbind = (?P<vbindex>\d+)"
    )

    LF_FIELDLIST_ENUMERATE = re.compile(
        r"list\[\d+\] = LF_ENUMERATE,.*value = (?P<value>\d+), name = '(?P<name>[^']+)'"
    )

    LF_ARRAY_RE = re.compile(
        r"\s+Element type = (?P<type>[^\n]+)\n\s+Index type = [^\n]+\n\s+length = (?:[\w()]+ )?(?P<length>\d+)\n"
    )

    # LF_CLASS/LF_STRUCTURE field list reference
    CLASS_FIELD_RE = re.compile(
        r"\s+# members = \d+,  field list type (?P<field_type>0x\w+),"
    )

    # LF_CLASS/LF_STRUCTURE name and other info
    CLASS_NAME_RE = re.compile(
        r"\s+Size = (?P<number_type>\([\w_]+\) )?(?P<size>\d+), class name = (?P<name>(?:[^\n,]|,\S)+)(?:, unique name = [^\n,]+)?(?:, UDT\((?P<udt>0x\w+)\))?"
    )

    # LF_MODIFIER, type being modified
    MODIFIES_RE = re.compile(r"\s+modifies type (?P<type>.*)")

    # LF_ARGLIST number of entries
    LF_ARGLIST_ARGCOUNT = re.compile(r".*argument count = (?P<argcount>\d+)")

    # LF_ARGLIST list entry
    LF_ARGLIST_ENTRY = re.compile(r"list\[(?P<index>\d+)\] = (?P<arg_type>[?\w()]+)")

    LF_POINTER_RE = re.compile(
        r"\s+(?P<type>.+\S) \(\w+\), Size: \d+\n\s+Element type : (?P<element_type>[^\n,]+)[\n,]"
    )

    LF_PROCEDURE_RE = re.compile(
        (
            r"\s+Return type = (?P<return_type>[^,]+), Call type = (?P<call_type>[^\n]+)\n"
            r"\s+Func attr = (?P<func_attr>[^\n]+)\n"
            r"\s+# Parms = (?P<num_params>\d+), Arg list type = (?P<arg_list_type>\w+)"
        )
    )

    LF_MFUNCTION_RE = re.compile(
        (
            r"\s+Return type = (?P<return_type>[^,]+), Class type = (?P<class_type>[^,]+), This type = (?P<this_type>[^,]+),\s*\n"
            r"\s+Call type = (?P<call_type>[^,]+), Func attr = (?P<func_attr>[^\n]+)\n"
            r"\s+Parms = (?P<num_params>\d+), Arg list type = (?P<arg_list_type>\w+), This adjust = (?P<this_adjust>[0-9a-f]+)"
        )
    )

    LF_ENUM_ATTRIBUTES = [
        re.compile(r"^\s*# members = (?P<num_members>\d+)$"),
        re.compile(r"^\s*enum name = (?P<name>.+)$"),
    ]
    LF_ENUM_TYPES = re.compile(
        r"^\s*type = (?P<underlying_type>\S+) field list type (?P<field_type>0x\w{4})$"
    )
    LF_ENUM_UDT = re.compile(r"^\s*UDT\((?P<udt>0x\w+)\)$")
    LF_UNION_LINE = re.compile(
        r"\s+field list type (?P<field_type>0x\w+),.*Size = (?P<size>\d+)\s*,class name = (?P<name>(?:[^\n,]|,\S)+)(?:, unique name = [^\n,]+)?(?:,\s.*UDT\((?P<udt>0x\w+)\))?"
    )

    MODES_OF_INTEREST = {
        "LF_ARRAY",
        "LF_CLASS",
        "LF_ENUM",
        "LF_FIELDLIST",
        "LF_MODIFIER",
        "LF_POINTER",
        "LF_STRUCTURE",
        "LF_ARGLIST",
        "LF_MFUNCTION",
        "LF_PROCEDURE",
        "LF_UNION",
    }

    def __init__(self) -> None:
        self.mode: str | None = None
        self.keys: dict[str, dict[str, Any]] = {}

    def _get_field_list(self, type_obj: dict[str, Any]) -> list[FieldListItem]:
        """Return the field list for the given LF_CLASS/LF_STRUCTURE reference"""

        if type_obj.get("type") == "LF_FIELDLIST":
            field_obj = type_obj
        else:
            field_list_type = type_obj["field_list_type"]
            field_obj = self.keys[field_list_type]

        members: list[FieldListItem] = []

        super_ids = field_obj.get("super", [])
        for super_id in super_ids:
            # May need to resolve forward ref.
            superclass = self.get(super_id)
            if superclass.members is not None:
                members += superclass.members

        raw_members = field_obj.get("members", [])
        members += [
            FieldListItem(
                offset=m["offset"],
                type=m["type"],
                name=m["name"],
            )
            for m in raw_members
        ]

        return sorted(members, key=lambda m: m.offset)

    def _mock_array_members(self, type_obj: dict[str, Any]) -> list[FieldListItem]:
        """LF_ARRAY elements provide the element type and the total size.
        We want the list of "members" as if this was a struct."""

        if type_obj.get("type") != "LF_ARRAY":
            raise CvdumpTypeError("Type is not an LF_ARRAY")

        array_type = type_obj.get("array_type")
        if array_type is None:
            raise CvdumpIntegrityError("No array element type")

        array_element_size = self.get(array_type).size
        assert (
            array_element_size is not None
        ), "Encountered an array whose type has no size"

        n_elements = type_obj["size"] // array_element_size

        return [
            FieldListItem(
                offset=i * array_element_size,
                type=array_type,
                name=f"[{i}]",
            )
            for i in range(n_elements)
        ]

    def get(self, type_key: str) -> TypeInfo:
        """Convert our dictionary values read from the cvdump output
        into a consistent format for the given type."""

        # Scalar type. Handled here because it makes the recursive steps
        # much simpler.
        if type_key.startswith("T_"):
            size = scalar_type_size(type_key)
            return TypeInfo(
                key=type_key,
                size=size,
            )

        # Go to our dictionary to find it.
        obj = self.keys.get(type_key.lower())
        if obj is None:
            raise CvdumpKeyError(type_key)

        # These type references are just a wrapper around a scalar
        if obj.get("type") == "LF_ENUM":
            underlying_type = obj.get("underlying_type")
            if underlying_type is None:
                raise CvdumpKeyError(f"Missing 'underlying_type' in {obj}")
            return self.get(underlying_type)

        if obj.get("type") == "LF_POINTER":
            return self.get("T_32PVOID")

        if obj.get("is_forward_ref", False):
            # Get the forward reference to follow.
            # If this is LF_CLASS/LF_STRUCTURE, it is the UDT value.
            # For LF_MODIFIER, it is the type being modified.
            forward_ref = obj.get("udt", None) or obj.get("modifies", None)
            if forward_ref is None:
                raise CvdumpIntegrityError(f"Null forward ref for type {type_key}")

            return self.get(forward_ref)

        # Else it is not a forward reference, so build out the object here.
        if obj.get("type") == "LF_ARRAY":
            members = self._mock_array_members(obj)
        else:
            members = self._get_field_list(obj)

        return TypeInfo(
            key=type_key,
            size=obj.get("size"),
            name=obj.get("name"),
            members=members,
        )

    def get_by_name(self, name: str) -> TypeInfo:
        """Find the complex type with the given name."""
        # TODO
        raise NotImplementedError

    def get_scalars(self, type_key: str) -> list[ScalarType]:
        """Reduce the given type to a list of scalars so we can
        compare each component value."""

        obj = self.get(type_key)
        if obj.is_scalar():
            # Use obj.key here for alias types like LF_POINTER
            return [ScalarType(offset=0, type=obj.key, name=None)]

        # mypy?
        assert obj.members is not None

        # Dedupe repeated offsets if this is a union type
        unique_offsets = {m.offset: m for m in obj.members}
        unique_members = [m for _, m in unique_offsets.items()]

        return [
            ScalarType(
                offset=m.offset + cm.offset,
                type=cm.type,
                name=join_member_names(m.name, cm.name),
            )
            for m in unique_members
            for cm in self.get_scalars(m.type)
        ]

    def get_scalars_gapless(self, type_key: str) -> list[ScalarType]:
        """Reduce the given type to a list of scalars so we can
        compare each component value."""

        obj = self.get(type_key)
        total_size = obj.size
        assert (
            total_size is not None
        ), "Called get_scalar_gapless() on a type without size"

        scalars = self.get_scalars(type_key)

        output: list[ScalarType] = []
        last_extent = total_size

        # Walk the scalar list in reverse; we assume a gap could not
        # come at the start of the struct.
        for scalar in scalars[::-1]:
            this_extent = scalar.offset + scalar_type_size(scalar.type)
            size_diff = last_extent - this_extent
            # We need to add the gap fillers in reverse here
            for i in range(size_diff - 1, -1, -1):
                # Push to front
                output.insert(
                    0,
                    ScalarType(
                        offset=this_extent + i,
                        name="(padding)",
                        type="T_UCHAR",
                    ),
                )

            output.insert(0, scalar)
            last_extent = scalar.offset

        return output

    def get_format_string(self, type_key: str) -> str:
        members = self.get_scalars_gapless(type_key)
        return member_list_to_struct_string(members)

    def read_all(self, section: str):
        r_leafsplit = re.compile(r"\n(?=0x\w{4} : )")
        for leaf in r_leafsplit.split(section):
            if (match := self.INDEX_RE.match(leaf)) is None:
                continue

            (leaf_id, leaf_type) = match.groups()
            if leaf_type not in self.MODES_OF_INTEREST:
                self.mode = None
                continue

            # Add the leaf to our dictionary and add details specific to the leaf type.
            self.mode = leaf_type
            self.keys[leaf_id] = {"type": leaf_type}

            this_key = self.keys[leaf_id]

            try:
                if self.mode == "LF_MODIFIER":
                    this_key.update(self.read_modifier(leaf))

                elif self.mode == "LF_ARRAY":
                    this_key.update(self.read_array(leaf))

                elif self.mode == "LF_FIELDLIST":
                    this_key.update(self.read_fieldlist(leaf))

                elif self.mode == "LF_ARGLIST":
                    this_key.update(self.read_arglist(leaf))

                elif self.mode == "LF_MFUNCTION":
                    this_key.update(self.read_mfunction(leaf))

                elif self.mode == "LF_PROCEDURE":
                    this_key.update(self.read_procedure(leaf))

                elif self.mode in ["LF_CLASS", "LF_STRUCTURE"]:
                    this_key.update(self.read_class_or_struct(leaf))

                elif self.mode == "LF_POINTER":
                    this_key.update(self.read_pointer(leaf))

                elif self.mode == "LF_ENUM":
                    this_key.update(self.read_enum(leaf))

                elif self.mode == "LF_UNION":
                    this_key.update(self.read_union(leaf))
                else:
                    # Check for exhaustiveness
                    logger.error("Unhandled data in mode: %s", self.mode)

            except AssertionError:
                logger.error("Failed to parse PDB types leaf:\n%s", leaf)

    def read_modifier(self, leaf: str) -> dict[str, Any]:
        match = self.MODIFIES_RE.search(leaf)
        assert match is not None

        # For convenience, because this is essentially the same thing
        # as an LF_CLASS forward ref.
        return {
            "is_forward_ref": True,
            "modifies": normalize_type_id(match.group("type")),
        }

    def read_array(self, leaf: str) -> dict[str, Any]:
        match = self.LF_ARRAY_RE.search(leaf)
        assert match is not None

        return {
            "array_type": normalize_type_id(match.group("type")),
            "size": int(match.group("length")),
        }

    def read_fieldlist(self, leaf: str) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        members = []

        # If this class has a vtable, create a mock member at offset 0
        if self.VTABLE_RE.search(leaf) is not None:
            # For our purposes, any pointer type will do
            members.append({"offset": 0, "type": "T_32PVOID", "name": "vftable"})

        # Superclass is set here in the fieldlist rather than in LF_CLASS
        for match in self.SUPERCLASS_RE.finditer(leaf):
            superclass_list: dict[str, int] = obj.setdefault("super", {})
            superclass_list[normalize_type_id(match.group("type"))] = int(
                match.group("offset")
            )

        # virtual base class (direct or indirect)
        for match in self.VBCLASS_RE.finditer(leaf):
            virtual_base_pointer = obj.setdefault(
                "vbase",
                VirtualBasePointer(
                    vboffset=-1,  # default to -1 until we parse the correct value
                    bases=[],
                ),
            )
            assert isinstance(
                virtual_base_pointer, VirtualBasePointer
            )  # type checker only

            virtual_base_pointer.bases.append(
                VirtualBaseClass(
                    type=match.group("type"),
                    index=-1,  # default to -1 until we parse the correct value
                    direct=match.group("indirect") != "I",
                )
            )

            vboffset = int(match.group("vboffset"))

            if virtual_base_pointer.vboffset == -1:
                # default value
                virtual_base_pointer.vboffset = vboffset
            elif virtual_base_pointer.vboffset != vboffset:
                # vboffset is always equal to 4 in our examples. We are not sure if there can be multiple
                # virtual base pointers, and if so, how the layout is supposed to look.
                # We therefore assume that there is always only one virtual base pointer.
                logger.error(
                    "Unhandled: Found multiple virtual base pointers at offsets %d and %d",
                    virtual_base_pointer.vboffset,
                    vboffset,
                )

            virtual_base_pointer.bases[-1].index = int(match.group("vbindex"))
            # these come out of order, and the lists are so short that it's fine to sort them every time
            virtual_base_pointer.bases.sort(key=lambda x: x.index)

        members += [
            {
                "offset": int(offset),
                "type": normalize_type_id(type_),
                "name": name,
            }
            for (_, type_, offset, name) in self.LIST_RE.findall(leaf)
        ]

        if members:
            obj["members"] = members

        variants = [
            {"name": name, "value": int(value)}
            for value, name in self.LF_FIELDLIST_ENUMERATE.findall(leaf)
        ]
        if variants:
            obj["variants"] = variants

        return obj

    def read_class_or_struct(self, leaf: str) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        # Match the reference to the associated LF_FIELDLIST
        match = self.CLASS_FIELD_RE.search(leaf)
        assert match is not None
        if match.group("field_type") == "0x0000":
            # Not redundant. UDT might not match the key.
            # These cases get reported as UDT mismatch.
            obj["is_forward_ref"] = True
        else:
            field_list_type = normalize_type_id(match.group("field_type"))
            obj["field_list_type"] = field_list_type

        match = self.CLASS_NAME_RE.search(leaf)
        assert match is not None
        # Last line has the vital information.
        # If this is a FORWARD REF, we need to follow the UDT pointer
        # to get the actual class details.
        obj["name"] = match.group("name")
        udt = match.group("udt")
        if udt is not None:
            obj["udt"] = normalize_type_id(udt)

        obj["size"] = int(match.group("size"))

        return obj

    def read_arglist(self, leaf: str) -> dict[str, Any]:
        match = self.LF_ARGLIST_ARGCOUNT.match(leaf)
        assert match is not None
        argcount = int(match.group("argcount"))

        arglist = [arg_type for (_, arg_type) in self.LF_ARGLIST_ENTRY.findall(leaf)]
        assert len(arglist) == argcount

        obj: dict[str, Any] = {"argcount": argcount}
        # Set the arglist only when argcount > 0
        if arglist:
            obj["args"] = arglist

        return obj

    def read_pointer(self, leaf: str) -> dict[str, Any]:
        match = self.LF_POINTER_RE.search(leaf)
        assert match is not None

        # We don't use the pointer type, but we still want to check for exhaustiveness
        # in case we missed some relevant data
        assert match.group("type") in (
            "R-value Reference",
            "Pointer",
            "const Pointer",
            "L-value Reference",
            "volatile Pointer",
            "volatile const Pointer",
            "Pointer to member",
            "Pointer to member function",
        )

        return {"element_type": match.group("element_type")}

    def read_mfunction(self, leaf: str) -> dict[str, Any]:
        match = self.LF_MFUNCTION_RE.search(leaf)
        assert match is not None
        return match.groupdict()

    def read_procedure(self, leaf: str) -> dict[str, Any]:
        match = self.LF_PROCEDURE_RE.search(leaf)
        assert match is not None
        return match.groupdict()

    def read_enum(self, leaf: str) -> dict[str, Any]:
        obj: dict[str, Any] = {}

        # TODO: still parsing each line for now
        for line in leaf.splitlines()[1:]:
            if not line:
                continue
            # We need special comma handling because commas may appear in the name.
            # Splitting by "," yields the wrong result.
            enum_attributes = line.split(", ")
            for pair in enum_attributes:
                if pair.endswith(","):
                    pair = pair[:-1]
                if pair.isspace():
                    continue
                obj |= self.parse_enum_attribute(pair)

        return obj

    def parse_enum_attribute(self, attribute: str) -> dict[str, Any]:
        for attribute_regex in self.LF_ENUM_ATTRIBUTES:
            if (match := attribute_regex.match(attribute)) is not None:
                return match.groupdict()
        if attribute == "NESTED":
            return {"is_nested": True}
        if attribute == "FORWARD REF":
            return {"is_forward_ref": True}
        if attribute == "LOCAL":
            # Present as early as MSVC 7.00; not sure what is significance is and/or if we need it for anything
            return {}
        if attribute.startswith("UDT"):
            match = self.LF_ENUM_UDT.match(attribute)
            assert match is not None
            return {"udt": normalize_type_id(match.group("udt"))}
        if (match := self.LF_ENUM_TYPES.match(attribute)) is not None:
            result = match.groupdict()
            result["underlying_type"] = normalize_type_id(result["underlying_type"])
            return result
        logger.error("Unknown attribute in enum: %s", attribute)
        return {}

    def read_union(self, leaf: str) -> dict[str, Any]:
        """This is a rather barebones handler, only parsing the size"""
        match = self.LF_UNION_LINE.search(leaf)
        assert match is not None

        obj: dict[str, Any] = {"name": match.group("name")}

        if match.group("field_type") == "0x0000":
            obj["is_forward_ref"] = True

        obj["field_list_type"] = match.group("field_type")
        obj["size"] = int(match.group("size"))
        if match.group("udt") is not None:
            obj["udt"] = normalize_type_id(match.group("udt"))

        return obj
