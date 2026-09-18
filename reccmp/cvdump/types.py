import bisect
import re
import logging
from typing import NamedTuple
from .cvinfo import (
    CvInfoType,
    CvdumpTypeKey,
    CVInfoTypeEnum,
    CvdumpTypeMap,
)
from .type_leaves import (
    CvdumpParsedType,
    FieldListItem,
    read_arglist,
    read_array,
    read_bitfield,
    read_class_or_struct,
    read_enum,
    read_fieldlist,
    read_mfunction,
    read_modifier,
    read_pointer,
    read_procedure,
    read_union,
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


def get_best_member_item(
    members: list[FieldListItem], offset: int
) -> FieldListItem | None:
    """Find the member that equals or is closest to our offset.
    Unions and bitfields may have multiple candidates with the same offset.
    In that case, use the first one."""
    if not members:
        return None

    i = bisect.bisect_left(members, offset, key=lambda mem: mem.offset)
    j = bisect.bisect_right(members, offset, key=lambda mem: mem.offset)

    # If the indices are equal, our offset is between two field list items.
    # Use one index earlier because it contains the offset.
    if i == j:
        i = max(0, i - 1)

    for mem in members[i:j]:
        return mem

    return None


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
    """The unique identifier from the PDB."""
    size: int | None
    """Total size of this type in bytes."""
    name: str | None = None
    """Optional name for this complex type."""
    members: list[FieldListItem] | None = None
    """Struct only: List of members in this struct or class."""
    array_type: CvdumpTypeKey | None = None
    """Array only: Underlying type of each array element."""
    array_length: int | None = None
    """Array only: Count of elements in the array."""
    array_element_size: int | None = None
    """Array only: Size in bytes of each array element."""

    def is_struct(self) -> bool:
        return self.members is not None

    def is_array(self) -> bool:
        return self.array_type is not None

    def is_scalar(self) -> bool:
        # TODO: distinction between a class with zero members and no vtable?
        return self.members is None and self.array_type is None


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

    MODES_OF_INTEREST = {
        "LF_ARRAY",
        "LF_BITFIELD",
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
        self._keys: dict[CvdumpTypeKey, CvdumpParsedType] = {}
        self._raw: dict[CvdumpTypeKey, tuple[str, str]] = {}
        self.alerted_types: set[int] = set()

    def from_key(self, type_key: CvdumpTypeKey) -> CvdumpParsedType:
        try:
            return self._keys[type_key]
        except KeyError:
            pass

        return self._parse_raw(type_key)

    def _get_field_list(self, type_obj: CvdumpParsedType) -> list[FieldListItem]:
        """Return the field list for the given LF_CLASS/LF_STRUCTURE reference"""

        if type_obj.get("type") == "LF_FIELDLIST":
            field_obj = type_obj
        else:
            field_list_type = type_obj["field_list_type"]
            field_obj = self.from_key(field_list_type)

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
        obj = self.from_key(type_key)
        obj_type = obj.get("type")

        if obj_type == "LF_POINTER":
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
        if obj_type == "LF_ENUM":
            underlying_type = obj.get("underlying_type")
            if underlying_type is None:
                raise CvdumpKeyError(f"Missing 'underlying_type' in {obj}")

            return self.get(underlying_type)

        members = None
        array_type = None
        array_length = None
        array_element_size = None

        # Else it is not a forward reference, so build out the object here.
        if obj_type == "LF_ARRAY":
            array_type = obj.get("array_type")
            if array_type is None:
                raise CvdumpIntegrityError("No array element type")

            array_element_size = self.get(array_type).size
            assert (
                array_element_size is not None
            ), "Encountered an array whose type has no size"

            assert "size" in obj, "Cannot reconstruct array without total size"
            array_length = obj["size"] // array_element_size

        elif obj_type in ("LF_CLASS", "LF_STRUCTURE", "LF_UNION", "LF_FIELDLIST"):
            members = self._get_field_list(obj)
        elif obj_type in ("LF_BITFIELD",):
            res = self.get(obj["bit_type"])
            return res

        return TypeInfo(
            key=type_key,
            size=obj.get("size"),
            name=obj.get("name"),
            members=members,
            array_type=array_type,
            array_length=array_length,
            array_element_size=array_element_size,
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

        if obj.is_array():
            assert obj.array_type is not None
            assert obj.array_length is not None
            assert obj.array_element_size is not None

            array_element_members = self.get_scalars(obj.array_type)

            return [
                ScalarType(
                    offset=i * obj.array_element_size + cm.offset,
                    type=cm.type,
                    name=join_member_names(f"[{i}]", cm.name),
                )
                for i in range(obj.array_length)
                for cm in array_element_members
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

        # Deduplicate overlapping scalars that come from union members.
        # get_scalars() dedupes union members at the outermost level only:
        # if a union has branches whose inner members span different
        # byte offsets (e.g. DEVMODE's union of POINTL vs four shorts),
        # the flattened scalars from one branch can overlap with the
        # other branch. Sort by offset, then pick the largest-size scalar
        # at each offset and skip any subsequent scalar that falls within
        # the range we've already claimed.
        scalars = sorted(scalars, key=lambda s: (s.offset, -s.size))
        deduped: list[ScalarType] = []
        next_offset = 0
        for scalar in scalars:
            if scalar.offset >= next_offset:
                deduped.append(scalar)
                next_offset = scalar.offset + scalar.size
        scalars = deduped

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

    def get_name_for_offset(self, type_key: CvdumpTypeKey, offset: int) -> str:
        """Limited to arrays for now. Enable to close GH #462."""
        if type_key in self._raw:
            type_dict = self.from_key(type_key)
            if type_dict.get("type") != "LF_ARRAY":
                return f"+{offset}" if offset > 0 else ""

        names = []

        # 2 levels max depth (for now)
        for _ in range(2):
            try:
                obj = self.get(type_key)
            except CvdumpKeyError:
                break

            if obj.is_scalar():
                break

            if obj.is_array():
                assert obj.array_type is not None
                assert obj.array_element_size is not None

                array_idx = offset // obj.array_element_size
                type_key = obj.array_type
                offset -= array_idx * obj.array_element_size
                names.append(f"[{array_idx}]")

            else:
                assert isinstance(obj.members, list)
                mem = get_best_member_item(obj.members, offset)
                if mem is None:
                    # Negative offset?
                    break

                type_key = mem.type
                offset -= mem.offset
                names.append(f".{mem.name}")

        if offset > 0:
            names.append(f"+{offset}")

        return "".join(names)

    def get_format_string(self, type_key: CvdumpTypeKey) -> str:
        members = self.get_scalars_gapless(type_key)
        return member_list_to_struct_string(members)

    def _parse_raw(self, leaf_id: CvdumpTypeKey) -> CvdumpParsedType:
        try:
            leaf, leaf_type = self._raw[leaf_id]
        except KeyError as ex:
            raise CvdumpKeyError from ex

        try:
            match leaf_type:
                case "LF_MODIFIER":
                    self._keys[leaf_id] = read_modifier(leaf, leaf_type)

                case "LF_ARRAY":
                    self._keys[leaf_id] = read_array(leaf, leaf_type)

                case "LF_FIELDLIST":
                    self._keys[leaf_id] = read_fieldlist(leaf, leaf_type)

                case "LF_ARGLIST":
                    self._keys[leaf_id] = read_arglist(leaf, leaf_type)

                case "LF_MFUNCTION":
                    self._keys[leaf_id] = read_mfunction(leaf, leaf_type)

                case "LF_PROCEDURE":
                    self._keys[leaf_id] = read_procedure(leaf, leaf_type)

                case "LF_CLASS" | "LF_STRUCTURE":
                    self._keys[leaf_id] = read_class_or_struct(leaf, leaf_type)

                case "LF_POINTER":
                    self._keys[leaf_id] = read_pointer(leaf, leaf_type)

                case "LF_ENUM":
                    self._keys[leaf_id] = read_enum(leaf, leaf_type)

                case "LF_UNION":
                    self._keys[leaf_id] = read_union(leaf, leaf_type)

                case "LF_BITFIELD":
                    self._keys[leaf_id] = read_bitfield(leaf, leaf_type)

                case _:
                    # Check for exhaustiveness
                    logger.error("Unhandled leaf type: %s", leaf_type)

        except AssertionError:
            logger.error("Failed to parse PDB types leaf:\n%s", leaf)

        return self._keys[leaf_id]

    def read_all(self, section: str):
        r_leafsplit = re.compile(r"\n(?=0x\w{4,8} : )")
        for leaf in r_leafsplit.split(section):
            if (match := self.INDEX_RE.match(leaf)) is None:
                continue

            leaf_id_str, leaf_type = match.groups()
            if leaf_type in self.MODES_OF_INTEREST:
                leaf_id = CvdumpTypeKey.from_str(leaf_id_str)
                self._raw[leaf_id] = (leaf, leaf_type)
