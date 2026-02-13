from dataclasses import dataclass
import re
import logging
from typing import NamedTuple
from typing_extensions import NotRequired, TypedDict
from .cvinfo import (
    CvInfoType,
    CvdumpTypeKey,
    CVInfoTypeEnum,
    CvdumpTypeMap,
)


logger = logging.getLogger(__name__)


class CvdumpTypeError(Exception):
    pass


class CvdumpKeyError(KeyError):
    pass


class CvdumpIntegrityError(Exception):
    pass


def get_primitive(key: CvdumpTypeKey) -> CvInfoType:
    """Throw CvdumpKeyError if we get a KeyError from the primitive map.
    Log an error for the invalid type whether the exception is caught or not."""
    try:
        return CvdumpTypeMap[key]
    except KeyError as ex:
        logger.error("Unknown scalar type 0x%x", key)
        raise CvdumpKeyError(key) from ex


class FieldListItem(NamedTuple):
    """Member of a class or structure"""

    offset: int
    name: str
    type: CvdumpTypeKey


class EnumItem(NamedTuple):
    name: str
    value: int


@dataclass
class VirtualBaseClass:
    type: CvdumpTypeKey
    index: int
    direct: bool


@dataclass
class VirtualBasePointer:
    vboffset: int
    bases: list[VirtualBaseClass]


class ScalarType(NamedTuple):
    offset: int
    name: str | None
    type: CvInfoType

    @property
    def size(self) -> int:
        return self.type.size

    @property
    def format_char(self) -> str:
        return self.type.fmt

    @property
    def is_pointer(self) -> bool:
        return self.type.pointer is not None


class TypeInfo(NamedTuple):
    key: CvdumpTypeKey
    size: int | None
    name: str | None = None
    members: list[FieldListItem] | None = None

    def is_scalar(self) -> bool:
        # TODO: distinction between a class with zero members and no vtable?
        return self.members is None


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


class LfEnumAttrs(TypedDict):
    field_list_type: NotRequired[CvdumpTypeKey]
    is_forward_ref: NotRequired[bool]
    is_nested: NotRequired[bool]
    name: NotRequired[str]
    num_members: NotRequired[int]
    udt: NotRequired[CvdumpTypeKey]
    underlying_type: NotRequired[CvdumpTypeKey]


class CvdumpParsedType(TypedDict):
    type: str  # leaf type

    # Used by many leaf types
    name: NotRequired[str]
    size: NotRequired[int]
    is_forward_ref: NotRequired[bool]
    field_list_type: NotRequired[CvdumpTypeKey]
    udt: NotRequired[CvdumpTypeKey]

    # LF_ARRAY
    array_type: NotRequired[CvdumpTypeKey]

    # LF_ENUM
    is_nested: NotRequired[bool]
    num_members: NotRequired[int]
    underlying_type: NotRequired[CvdumpTypeKey]

    # LF_MODIFIER
    modifies: NotRequired[CvdumpTypeKey]
    modification: NotRequired[str]

    # LF_FIELDLIST
    super: NotRequired[dict[CvdumpTypeKey, int]]
    vbase: NotRequired[VirtualBasePointer]
    members: NotRequired[list[FieldListItem]]
    variants: NotRequired[list[EnumItem]]

    # LF_ARGLIST
    argcount: NotRequired[int]
    args: NotRequired[list[CvdumpTypeKey]]

    # LF_POINTER
    element_type: NotRequired[CvdumpTypeKey]
    containing_class: NotRequired[CvdumpTypeKey]
    pointer_type: NotRequired[str]

    # LF_PROCEDURE / LF_MFUNCTION
    return_type: NotRequired[CvdumpTypeKey]
    call_type: NotRequired[str]
    class_type: NotRequired[CvdumpTypeKey]
    this_type: NotRequired[CvdumpTypeKey]
    func_attr: NotRequired[str]
    num_params: NotRequired[int]
    arg_list_type: NotRequired[CvdumpTypeKey]
    this_adjust: NotRequired[int]


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
        r"list\[\d+\] = LF_BCLASS, (?P<scope>\w+), type = (?P<type>[^,]*), offset = (?P<offset>\d+)"
    )

    # LF_FIELDLIST virtual direct/indirect base pointer
    VBCLASS_RE = re.compile(
        r"list\[\d+\] = LF_(?P<indirect>I?)VBCLASS, .* base type = (?P<type>[^,]*)\n\s+virtual base ptr = [^,]+, vbpoff = (?P<vboffset>\d+), vbind = (?P<vbindex>\d+)"
    )

    LF_FIELDLIST_ENUMERATE = re.compile(
        r"list\[\d+\] = LF_ENUMERATE,.*value = (?P<value>\d+), name = '(?P<name>[^']+)'"
    )

    LF_ARRAY_RE = re.compile(
        r"\s+Element type = (?P<type>[^\n,]+)\n\s+Index type = [^\n]+\n\s+length = (?:[\w()]+ )?(?P<length>\d+)\n"
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
    MODIFIES_RE = re.compile(
        r"\n\s+(?P<modification>.+?), modifies type (?P<type>[^\n,]*)"
    )

    # LF_ARGLIST number of entries
    LF_ARGLIST_ARGCOUNT = re.compile(r".*argument count = (?P<argcount>\d+)")

    # LF_ARGLIST list entry
    LF_ARGLIST_ENTRY = re.compile(r"list\[(?P<index>\d+)\] = (?P<arg_type>[?\w()]+)")

    LF_POINTER_RE = re.compile(
        r"\s+(?P<type>.+\S) \(\w+\), Size: \d+\n\s+Element type : (?P<element_type>[^\n,]+)(?:, Containing class = (?P<containing_class>[^,]+),)?[\n,]"
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
            r"\s+Call type = (?P<call_type>[^,]+), Func attr = (?P<func_attr>[^\n,]+)\n"
            r"\s+Parms = (?P<num_params>\d+), Arg list type = (?P<arg_list_type>\w+), This adjust = (?P<this_adjust>[0-9a-f]+)"
        )
    )

    LF_ENUM_MEMBER_RE = re.compile(r"^\s*# members = (?P<num_members>\d+)$")
    # the enum name can have both commas and whitespace, so '.+' is okay
    LF_ENUM_NAME_RE = re.compile(r"^\s*enum name = (?P<name>.+)$")

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
        self.keys: dict[CvdumpTypeKey, CvdumpParsedType] = {}
        self.alerted_types: set[int] = set()

    def _get_field_list(self, type_obj: CvdumpParsedType) -> list[FieldListItem]:
        """Return the field list for the given LF_CLASS/LF_STRUCTURE reference"""

        if type_obj.get("type") == "LF_FIELDLIST":
            field_obj = type_obj
        else:
            field_list_type = type_obj["field_list_type"]
            field_obj = self.keys[field_list_type]

        members: list[FieldListItem] = []

        if "super" in field_obj:
            for super_id in field_obj["super"].keys():
                # May need to resolve forward ref.
                superclass = self.get(super_id)
                if superclass.members is not None:
                    members += superclass.members

        raw_members = field_obj.get("members", [])
        members += raw_members

        return sorted(members, key=lambda m: m.offset)

    def _mock_array_members(self, type_obj: CvdumpParsedType) -> list[FieldListItem]:
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

    def get(self, type_key: CvdumpTypeKey) -> TypeInfo:
        """Convert our dictionary values read from the cvdump output
        into a consistent format for the given type."""

        # Scalar type. Handled here because it makes the recursive steps
        # much simpler.
        if type_key.is_scalar():
            cvinfo = get_primitive(type_key)
            # We have seen some of the primitive types so far, but not all.
            # The information in cvinfo.h is probably fine for most cases
            # but warn users if we are dealing with an unseen type.
            # (If you see this message in your project, we want to hear about it!)
            if not cvinfo.verified and cvinfo.key not in self.alerted_types:
                self.alerted_types.add(cvinfo.key)
                logger.info(
                    "Unverified primitive type 0x%04x '%s'",
                    cvinfo.key,
                    cvinfo.name,
                )

            return TypeInfo(
                key=type_key,
                size=cvinfo.size,
            )

        # Go to our dictionary to find it.
        obj = self.keys.get(type_key)
        if obj is None:
            raise CvdumpKeyError(type_key)

        if obj.get("type") == "LF_POINTER":
            return self.get(CVInfoTypeEnum.T_32PVOID)

        if obj.get("is_forward_ref", False):
            # Get the forward reference to follow.
            # If this is LF_CLASS/LF_STRUCTURE, it is the UDT value.
            # For LF_MODIFIER, it is the type being modified.
            forward_ref = obj.get("udt", None) or obj.get("modifies", None)
            if forward_ref is None:
                raise CvdumpIntegrityError(f"Null forward ref for type {type_key}")

            return self.get(forward_ref)

        # These type references are just a wrapper around a scalar
        if obj.get("type") == "LF_ENUM":
            underlying_type = obj.get("underlying_type")
            if underlying_type is None:
                raise CvdumpKeyError(f"Missing 'underlying_type' in {obj}")

            return self.get(underlying_type)

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

    def get_scalars(self, type_key: CvdumpTypeKey) -> list[ScalarType]:
        """Reduce the given type to a list of scalars so we can
        compare each component value."""

        obj = self.get(type_key)
        if obj.is_scalar():
            # Use obj.key here for alias types like LF_POINTER
            cvinfo = get_primitive(obj.key)
            return [
                ScalarType(
                    offset=0,
                    type=cvinfo,
                    name=None,
                )
            ]

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

    def get_scalars_gapless(self, type_key: CvdumpTypeKey) -> list[ScalarType]:
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
            this_extent = scalar.offset + scalar.size
            size_diff = last_extent - this_extent
            # We need to add the gap fillers in reverse here
            for i in range(size_diff - 1, -1, -1):
                # Push to front
                output.insert(
                    0,
                    ScalarType(
                        offset=this_extent + i,
                        name="(padding)",
                        type=get_primitive(CVInfoTypeEnum.T_UCHAR),
                    ),
                )

            output.insert(0, scalar)
            last_extent = scalar.offset

        return output

    def get_format_string(self, type_key: CvdumpTypeKey) -> str:
        members = self.get_scalars_gapless(type_key)
        return member_list_to_struct_string(members)

    def read_all(self, section: str):
        r_leafsplit = re.compile(r"\n(?=0x\w{4,8} : )")
        for leaf in r_leafsplit.split(section):
            if (match := self.INDEX_RE.match(leaf)) is None:
                continue

            (leaf_id_str, leaf_type) = match.groups()
            leaf_id = CvdumpTypeKey.from_str(leaf_id_str)
            if leaf_type not in self.MODES_OF_INTEREST:
                continue

            try:
                match leaf_type:
                    case "LF_MODIFIER":
                        self.keys[leaf_id] = self.read_modifier(leaf, leaf_type)

                    case "LF_ARRAY":
                        self.keys[leaf_id] = self.read_array(leaf, leaf_type)

                    case "LF_FIELDLIST":
                        self.keys[leaf_id] = self.read_fieldlist(leaf, leaf_type)

                    case "LF_ARGLIST":
                        self.keys[leaf_id] = self.read_arglist(leaf, leaf_type)

                    case "LF_MFUNCTION":
                        self.keys[leaf_id] = self.read_mfunction(leaf, leaf_type)

                    case "LF_PROCEDURE":
                        self.keys[leaf_id] = self.read_procedure(leaf, leaf_type)

                    case "LF_CLASS" | "LF_STRUCTURE":
                        self.keys[leaf_id] = self.read_class_or_struct(leaf, leaf_type)

                    case "LF_POINTER":
                        self.keys[leaf_id] = self.read_pointer(leaf, leaf_type)

                    case "LF_ENUM":
                        self.keys[leaf_id] = self.read_enum(leaf, leaf_type)

                    case "LF_UNION":
                        self.keys[leaf_id] = self.read_union(leaf, leaf_type)

                    case _:
                        # Check for exhaustiveness
                        logger.error("Unhandled data in mode: %s", leaf_type)

            except AssertionError:
                logger.error("Failed to parse PDB types leaf:\n%s", leaf)

    def read_modifier(self, leaf: str, leaf_type: str) -> CvdumpParsedType:
        match = self.MODIFIES_RE.search(leaf)
        assert match is not None

        # For convenience, because this is essentially the same thing
        # as an LF_CLASS forward ref.
        return {
            "type": leaf_type,
            "is_forward_ref": True,
            "modifies": CvdumpTypeKey.from_str(match.group("type")),
            "modification": match.group("modification"),
        }

    def read_array(self, leaf: str, leaf_type: str) -> CvdumpParsedType:
        match = self.LF_ARRAY_RE.search(leaf)
        assert match is not None

        return {
            "type": leaf_type,
            "array_type": CvdumpTypeKey.from_str(match.group("type")),
            "size": int(match.group("length")),
        }

    def read_fieldlist(self, leaf: str, leaf_type: str) -> CvdumpParsedType:
        obj: CvdumpParsedType = {"type": leaf_type}
        members: list[FieldListItem] = []

        # If this class has a vtable, create a mock member at offset 0
        if self.VTABLE_RE.search(leaf) is not None:
            # For our purposes, any pointer type will do
            members.append(
                FieldListItem(offset=0, type=CVInfoTypeEnum.T_32PVOID, name="vftable")
            )

        # Superclass is set here in the fieldlist rather than in LF_CLASS
        for match in self.SUPERCLASS_RE.finditer(leaf):
            superclass_list: dict[CvdumpTypeKey, int] = obj.setdefault("super", {})
            superclass_list[CvdumpTypeKey.from_str(match.group("type"))] = int(
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
                    type=CvdumpTypeKey.from_str(match.group("type")),
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
            FieldListItem(
                offset=int(offset),
                type=CvdumpTypeKey.from_str(type_),
                name=name,
            )
            for (_, type_, offset, name) in self.LIST_RE.findall(leaf)
        ]

        if members:
            obj["members"] = members

        variants = [
            EnumItem(name=name, value=int(value))
            for value, name in self.LF_FIELDLIST_ENUMERATE.findall(leaf)
        ]
        if variants:
            obj["variants"] = variants

        return obj

    def read_class_or_struct(self, leaf: str, leaf_type: str) -> CvdumpParsedType:
        obj: CvdumpParsedType = {"type": leaf_type}
        # Match the reference to the associated LF_FIELDLIST
        match = self.CLASS_FIELD_RE.search(leaf)
        assert match is not None
        if match.group("field_type") == "0x0000":
            # Not redundant. UDT might not match the key.
            # These cases get reported as UDT mismatch.
            obj["is_forward_ref"] = True
        else:
            field_list_type = CvdumpTypeKey.from_str(match.group("field_type"))
            obj["field_list_type"] = field_list_type

        match = self.CLASS_NAME_RE.search(leaf)
        assert match is not None
        # Last line has the vital information.
        # If this is a FORWARD REF, we need to follow the UDT pointer
        # to get the actual class details.
        obj["name"] = match.group("name")
        udt = match.group("udt")
        if udt is not None:
            obj["udt"] = CvdumpTypeKey.from_str(udt)

        obj["size"] = int(match.group("size"))

        return obj

    def read_arglist(self, leaf: str, leaf_type: str) -> CvdumpParsedType:
        match = self.LF_ARGLIST_ARGCOUNT.match(leaf)
        assert match is not None
        argcount = int(match.group("argcount"))

        arglist = [
            CvdumpTypeKey.from_str(arg_type)
            for (_, arg_type) in self.LF_ARGLIST_ENTRY.findall(leaf)
        ]
        assert len(arglist) == argcount

        obj: CvdumpParsedType = {"type": leaf_type, "argcount": argcount}
        # Set the arglist only when argcount > 0
        if arglist:
            obj["args"] = arglist

        return obj

    def read_pointer(self, leaf: str, leaf_type: str) -> CvdumpParsedType:
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

        obj: CvdumpParsedType = {
            "type": leaf_type,
            "element_type": CvdumpTypeKey.from_str(match.group("element_type")),
            "pointer_type": match.group("type"),
        }

        # `containing_class` is unset if not present
        if match.group("containing_class") is not None:
            obj["containing_class"] = CvdumpTypeKey.from_str(
                match.group("containing_class")
            )

        return obj

    def read_mfunction(self, leaf: str, leaf_type: str) -> CvdumpParsedType:
        match = self.LF_MFUNCTION_RE.search(leaf)
        assert match is not None
        return {
            "type": leaf_type,
            "return_type": CvdumpTypeKey.from_str(match.group("return_type")),
            "class_type": CvdumpTypeKey.from_str(match.group("class_type")),
            "this_type": CvdumpTypeKey.from_str(match.group("this_type")),
            "call_type": match.group("call_type"),
            "func_attr": match.group("func_attr"),
            "num_params": int(match.group("num_params")),
            "arg_list_type": CvdumpTypeKey.from_str(match.group("arg_list_type")),
            "this_adjust": int(match.group("this_adjust"), 16),
        }

    def read_procedure(self, leaf: str, leaf_type: str) -> CvdumpParsedType:
        match = self.LF_PROCEDURE_RE.search(leaf)
        assert match is not None
        return {
            "type": leaf_type,
            "return_type": CvdumpTypeKey.from_str(match.group("return_type")),
            "call_type": match.group("call_type"),
            "func_attr": match.group("func_attr"),
            "num_params": int(match.group("num_params")),
            "arg_list_type": CvdumpTypeKey.from_str(match.group("arg_list_type")),
        }

    def read_enum(self, leaf: str, leaf_type: str) -> CvdumpParsedType:
        obj: CvdumpParsedType = {"type": leaf_type}

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

    # pylint: disable=too-many-return-statements
    def parse_enum_attribute(self, attribute: str) -> LfEnumAttrs:
        if (match := self.LF_ENUM_MEMBER_RE.match(attribute)) is not None:
            return {"num_members": int(match.group("num_members"))}

        if (match := self.LF_ENUM_NAME_RE.match(attribute)) is not None:
            return {"name": match.group("name")}

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
            return {"udt": CvdumpTypeKey.from_str(match.group("udt"))}
        if (match := self.LF_ENUM_TYPES.match(attribute)) is not None:
            return {
                "underlying_type": CvdumpTypeKey.from_str(
                    match.group("underlying_type")
                ),
                "field_list_type": CvdumpTypeKey.from_str(match.group("field_type")),
            }

        logger.error("Unknown attribute in enum: %s", attribute)
        return {}

    def read_union(self, leaf: str, leaf_type: str) -> CvdumpParsedType:
        match = self.LF_UNION_LINE.search(leaf)
        assert match is not None

        obj: CvdumpParsedType = {"type": leaf_type, "name": match.group("name")}

        if match.group("field_type") == "0x0000":
            obj["is_forward_ref"] = True
        else:
            field_list_type = CvdumpTypeKey.from_str(match.group("field_type"))
            obj["field_list_type"] = field_list_type

        udt = match.group("udt")
        if udt is not None:
            obj["udt"] = CvdumpTypeKey.from_str(udt)

        obj["size"] = int(match.group("size"))

        return obj
