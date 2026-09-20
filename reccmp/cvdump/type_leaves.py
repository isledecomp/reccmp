"""Parsers for LF (leaf) text from the cvdump TYPES section."""

from dataclasses import dataclass
import re
import logging
from typing import NamedTuple
from typing_extensions import NotRequired, TypedDict
from .cvinfo import CvdumpTypeKey, CVInfoTypeEnum

logger = logging.getLogger(__name__)


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

    # LF_BITFIELD
    bit_start: NotRequired[int]
    bit_count: NotRequired[int]
    bit_type: NotRequired[CvdumpTypeKey]


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
    r"list\[\d+\] = LF_ENUMERATE,.*value = (?:\([\w_]*\)\s)?(?P<value>-?\d+)(?:\([\w_]*\))?, name = '(?P<name>[^']+)'"
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
MODIFIES_RE = re.compile(r"\n\s+(?P<modification>.+?), modifies type (?P<type>[^\n,]*)")

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
        r"\s+# Parms = (?P<num_params>\d+), Arg list type = (?P<arg_list_type>\w+)"  # codespell:ignore
    )
)

LF_MFUNCTION_RE = re.compile(
    (
        r"\s+Return type = (?P<return_type>[^,]+), Class type = (?P<class_type>[^,]+), This type = (?P<this_type>[^,]+),\s*\n"
        r"\s+Call type = (?P<call_type>[^,]+), Func attr = (?P<func_attr>[^\n,]+)\n"
        r"\s+Parms = (?P<num_params>\d+), Arg list type = (?P<arg_list_type>\w+), This adjust = (?P<this_adjust>[0-9a-f]+)"  # codespell:ignore
    )
)

LF_ENUM_MEMBER_RE = re.compile(r"^\s*# members = (?P<num_members>\d+)$")
# the enum name can have both commas and whitespace, so '.+' is okay
LF_ENUM_NAME_RE = re.compile(r"^\s*enum name = (?P<name>.+)$")

LF_ENUM_TYPES = re.compile(
    r"^\s*type = (?P<underlying_type>\S+) field list type (?P<field_type>0x\w+)$"
)
LF_ENUM_UDT = re.compile(r"^\s*UDT\((?P<udt>0x\w+)\)$")
LF_UNION_LINE = re.compile(
    r"\s+field list type (?P<field_type>0x\w+),.*Size = (?P<size>\d+)\s*,class name = (?P<name>(?:[^\n,]|,\S)+)(?:, unique name = [^\n,]+)?(?:,\s.*UDT\((?P<udt>0x\w+)\))?"
)

LF_BITFIELD_LINE = re.compile(
    r"bits = (?P<bitcount>[1-9][0-9]*), starting position = (?P<start>[0-9]*), Type = (?P<type_str>[^(]+)\((?P<type>[0-9a-fA-F]+)\)"
)


def read_modifier(leaf: str, leaf_type: str) -> CvdumpParsedType:
    match = MODIFIES_RE.search(leaf)
    assert match is not None

    # For convenience, because this is essentially the same thing
    # as an LF_CLASS forward ref.
    return {
        "type": leaf_type,
        "is_forward_ref": True,
        "modifies": CvdumpTypeKey.from_str(match.group("type")),
        "modification": match.group("modification"),
    }


def read_array(leaf: str, leaf_type: str) -> CvdumpParsedType:
    match = LF_ARRAY_RE.search(leaf)
    assert match is not None

    return {
        "type": leaf_type,
        "array_type": CvdumpTypeKey.from_str(match.group("type")),
        "size": int(match.group("length")),
    }


def read_fieldlist(leaf: str, leaf_type: str) -> CvdumpParsedType:
    obj: CvdumpParsedType = {"type": leaf_type}
    members: list[FieldListItem] = []

    # If this class has a vtable, create a mock member at offset 0
    if VTABLE_RE.search(leaf) is not None:
        # For our purposes, any pointer type will do
        members.append(
            FieldListItem(offset=0, type=CVInfoTypeEnum.T_32PVOID, name="vftable")
        )

    # Superclass is set here in the fieldlist rather than in LF_CLASS
    for match in SUPERCLASS_RE.finditer(leaf):
        superclass_list: dict[CvdumpTypeKey, int] = obj.setdefault("super", {})
        superclass_list[CvdumpTypeKey.from_str(match.group("type"))] = int(
            match.group("offset")
        )

    # virtual base class (direct or indirect)
    for match in VBCLASS_RE.finditer(leaf):
        virtual_base_pointer = obj.setdefault(
            "vbase",
            VirtualBasePointer(
                vboffset=-1,  # default to -1 until we parse the correct value
                bases=[],
            ),
        )
        assert isinstance(virtual_base_pointer, VirtualBasePointer)  # type checker only

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
        for (_, type_, offset, name) in LIST_RE.findall(leaf)
    ]

    if members:
        obj["members"] = members

    variants = [
        EnumItem(name=name, value=int(value))
        for value, name in LF_FIELDLIST_ENUMERATE.findall(leaf)
    ]
    if variants:
        obj["variants"] = variants

    return obj


def read_class_or_struct(leaf: str, leaf_type: str) -> CvdumpParsedType:
    obj: CvdumpParsedType = {"type": leaf_type}
    # Match the reference to the associated LF_FIELDLIST
    match = CLASS_FIELD_RE.search(leaf)
    assert match is not None
    if match.group("field_type") == "0x0000":
        # Not redundant. UDT might not match the key.
        # These cases get reported as UDT mismatch.
        obj["is_forward_ref"] = True
    else:
        field_list_type = CvdumpTypeKey.from_str(match.group("field_type"))
        obj["field_list_type"] = field_list_type

    match = CLASS_NAME_RE.search(leaf)
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


def read_arglist(leaf: str, leaf_type: str) -> CvdumpParsedType:
    match = LF_ARGLIST_ARGCOUNT.match(leaf)
    assert match is not None
    argcount = int(match.group("argcount"))

    arglist = [
        CvdumpTypeKey.from_str(arg_type)
        for (_, arg_type) in LF_ARGLIST_ENTRY.findall(leaf)
    ]
    assert len(arglist) == argcount

    obj: CvdumpParsedType = {"type": leaf_type, "argcount": argcount}
    # Set the arglist only when argcount > 0
    if arglist:
        obj["args"] = arglist

    return obj


def read_pointer(leaf: str, leaf_type: str) -> CvdumpParsedType:
    match = LF_POINTER_RE.search(leaf)
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


def read_mfunction(leaf: str, leaf_type: str) -> CvdumpParsedType:
    match = LF_MFUNCTION_RE.search(leaf)
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


def read_procedure(leaf: str, leaf_type: str) -> CvdumpParsedType:
    match = LF_PROCEDURE_RE.search(leaf)
    assert match is not None
    return {
        "type": leaf_type,
        "return_type": CvdumpTypeKey.from_str(match.group("return_type")),
        "call_type": match.group("call_type"),
        "func_attr": match.group("func_attr"),
        "num_params": int(match.group("num_params")),
        "arg_list_type": CvdumpTypeKey.from_str(match.group("arg_list_type")),
    }


def read_enum(leaf: str, leaf_type: str) -> CvdumpParsedType:
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
            obj |= parse_enum_attribute(pair)

    return obj


# pylint: disable=too-many-return-statements
def parse_enum_attribute(attribute: str) -> LfEnumAttrs:
    if (match := LF_ENUM_MEMBER_RE.match(attribute)) is not None:
        return {"num_members": int(match.group("num_members"))}

    if (match := LF_ENUM_NAME_RE.match(attribute)) is not None:
        return {"name": match.group("name")}

    if attribute == "NESTED":
        return {"is_nested": True}
    if attribute == "FORWARD REF":
        return {"is_forward_ref": True}
    if attribute == "LOCAL":
        # Present as early as MSVC 7.00; not sure what is significance is and/or if we need it for anything
        return {}
    if attribute.startswith("UDT"):
        match = LF_ENUM_UDT.match(attribute)
        assert match is not None
        return {"udt": CvdumpTypeKey.from_str(match.group("udt"))}
    if (match := LF_ENUM_TYPES.match(attribute)) is not None:
        return {
            "underlying_type": CvdumpTypeKey.from_str(match.group("underlying_type")),
            "field_list_type": CvdumpTypeKey.from_str(match.group("field_type")),
        }

    logger.error("Unknown attribute in enum: %s", attribute)
    return {}


def read_union(leaf: str, leaf_type: str) -> CvdumpParsedType:
    match = LF_UNION_LINE.search(leaf)
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


def read_bitfield(leaf: str, leaf_type: str) -> CvdumpParsedType:
    match = LF_BITFIELD_LINE.search(leaf)
    assert match is not None

    obj: CvdumpParsedType = {
        "type": leaf_type,
        "bit_start": int(match.group("start")),
        "bit_count": int(match.group("bitcount")),
        "bit_type": CvdumpTypeKey(int(match.group("type"), 16)),
    }

    return obj
