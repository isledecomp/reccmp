import re
import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import NamedTuple
from .cvinfo import (
    CvInfoType,
    CvdumpTypeKey,
    CvdumpTypeMap,
)
from .type_leaves import (
    CvdumpParsedType,
    EnumItem,
    FieldListItem,
    VirtualBaseClass,
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


class CvdumpValueError(ValueError):
    """The type key is incorrect for this operation."""


class CvdumpKeyError(KeyError):
    """The type key does not exist in the database."""


def get_primitive(key: CvdumpTypeKey) -> CvInfoType:
    """Throw CvdumpKeyError if we get a KeyError from the primitive map.
    Log an error for the invalid type whether the exception is caught or not."""
    try:
        return CvdumpTypeMap[key]
    except KeyError as ex:
        logger.error("Unknown scalar type 0x%x", key)
        raise CvdumpKeyError(key) from ex


class TypeKind(Enum):
    SCALAR = auto()
    POINTER = auto()
    ARRAY = auto()
    STRUCT = auto()
    UNION = auto()
    ENUM = auto()
    BITFIELD = auto()
    FUNCTION = auto()


LEAF_KINDS: dict[str, TypeKind] = {
    "LF_POINTER": TypeKind.POINTER,
    "LF_ARRAY": TypeKind.ARRAY,
    "LF_CLASS": TypeKind.STRUCT,
    "LF_STRUCTURE": TypeKind.STRUCT,
    "LF_UNION": TypeKind.UNION,
    "LF_ENUM": TypeKind.ENUM,
    "LF_BITFIELD": TypeKind.BITFIELD,
    "LF_PROCEDURE": TypeKind.FUNCTION,
    "LF_MFUNCTION": TypeKind.FUNCTION,
}


class TypeInfo(NamedTuple):
    key: CvdumpTypeKey
    """The unique identifier from the PDB."""
    kind: TypeKind
    """The category for this data type."""
    size: int | None
    """Total size of this type in bytes."""
    name: str | None
    """Optional name for this complex type."""


@dataclass
class FunctionInfo:
    call_type: str
    return_type: CvdumpTypeKey
    args: list[CvdumpTypeKey]
    class_type: CvdumpTypeKey | None
    this_adjust: int


@dataclass
class ClassInfo:
    has_vftable: bool
    vbptr_offset: int | None
    """vbpoff from the field list, or None if the class has no virtual bases."""
    virtual_bases: list[VirtualBaseClass]
    """Direct and indirect virtual base classes, sorted by vbind index."""


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

    def _primitive(self, type_key: CvdumpTypeKey) -> CvInfoType:
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

        return cvinfo

    def _resolved_leaf(self, type_key: CvdumpTypeKey) -> CvdumpParsedType:
        leaf = self.from_key(type_key)
        if leaf.get("is_forward_ref", False):
            raise CvdumpKeyError(f"Type {type_key} is a forward ref. Call get() first.")

        return leaf

    def _expect_leaf(
        self, type_key: CvdumpTypeKey, *leaf_types: str
    ) -> CvdumpParsedType:
        """Make sure that the given type key is backed by a specific leaf type."""
        if type_key.is_scalar():
            raise CvdumpValueError(f"{type_key} is scalar, expected {str(leaf_types)}")

        leaf = self._resolved_leaf(type_key)
        if leaf["type"] not in leaf_types:
            raise CvdumpValueError(
                f"{type_key} is {leaf['type']}, expected {str(leaf_types)}"
            )

        return leaf

    def _field_list(self, type_key: CvdumpTypeKey) -> CvdumpParsedType:
        leaf = self._expect_leaf(
            type_key, "LF_CLASS", "LF_STRUCTURE", "LF_UNION", "LF_ENUM"
        )
        return self.from_key(leaf["field_list_type"])

    # pylint:disable=too-many-return-statements
    def get(self, type_key: CvdumpTypeKey) -> TypeInfo:
        """Returns vital information (name, size, kind) for the type key.
        All processing should start here. Forward references are resolved if possible.
        The returned `key` value should be used in place of the input argument.
        If we cannot resolve the forward reference, return a `TypeInfo` with null size.
        """
        leaf: CvdumpParsedType | None = None

        # Follow any number of forward reference indirection hops.
        # TODO: Fix shortcut: LF_MODIFIER is considered a forward reference. (GH #574)
        # No consumer uses the `const` or `volatile` modifier options.
        while not type_key.is_scalar():
            leaf = self.from_key(type_key)
            if not leaf.get("is_forward_ref", False):
                break

            # For LF_CLASS/LF_STRUCTURE/LF_UNION/LF_ENUM, follow the UDT value.
            # For LF_MODIFIER, it is the type being modified.
            forward_ref = leaf.get("udt") or leaf.get("modifies")
            if forward_ref is None:
                # Example: HWND__
                kind = LEAF_KINDS.get(leaf["type"])
                if kind is None:
                    raise CvdumpKeyError(f"Null forward ref for type {type_key}")

                return TypeInfo(type_key, kind, None, leaf.get("name"))

            type_key = forward_ref

        if type_key.is_scalar():
            cvinfo = self._primitive(type_key)
            if cvinfo.pointer is not None:
                return TypeInfo(type_key, TypeKind.POINTER, cvinfo.size, None)

            return TypeInfo(type_key, TypeKind.SCALAR, cvinfo.size, None)

        assert leaf is not None
        kind = LEAF_KINDS.get(leaf["type"])
        match kind:
            case TypeKind.POINTER:
                # TODO: Assumes 32-bit pointers. (GH #573)
                return TypeInfo(type_key, kind, 4, None)

            case TypeKind.ARRAY:
                return TypeInfo(type_key, kind, leaf["size"], None)

            case TypeKind.STRUCT | TypeKind.UNION:
                return TypeInfo(type_key, kind, leaf["size"], leaf.get("name"))

            case TypeKind.ENUM:
                size = self.get(leaf["underlying_type"]).size
                return TypeInfo(type_key, kind, size, leaf.get("name"))

            case TypeKind.BITFIELD:
                size = self.get(leaf["bit_type"]).size
                return TypeInfo(type_key, kind, size, None)

            case TypeKind.FUNCTION:
                return TypeInfo(type_key, kind, None, None)

        raise CvdumpValueError(f"{type_key} is {leaf['type']}, cannot resolve")

    def element_type(self, type_key: CvdumpTypeKey) -> CvdumpTypeKey:
        """Return the type being referenced by the pointer or array."""
        if type_key.is_scalar():
            pointee_type = self._primitive(type_key).pointer
            if pointee_type is None:
                raise CvdumpValueError(f"{type_key} is not a pointer")

            return pointee_type

        leaf = self._expect_leaf(type_key, "LF_POINTER", "LF_ARRAY")
        if leaf["type"] == "LF_ARRAY":
            return leaf["array_type"]

        return leaf["element_type"]

    def underlying_type(self, type_key: CvdumpTypeKey) -> CvdumpTypeKey:
        """Returns the type footprint of the given enum or bitfield."""
        leaf = self._expect_leaf(type_key, "LF_ENUM", "LF_BITFIELD")
        if leaf["type"] == "LF_BITFIELD":
            return leaf["bit_type"]

        return leaf["underlying_type"]

    def members(self, type_key: CvdumpTypeKey) -> list[FieldListItem]:
        """Returns members of a struct or union. Order is not guaranteed. Callers should sort.
        Call `base_classes()` to access members from direct base classes."""
        self._expect_leaf(type_key, "LF_CLASS", "LF_STRUCTURE", "LF_UNION")

        return list(self._field_list(type_key).get("members", []))

    def base_classes(self, type_key: CvdumpTypeKey) -> dict[CvdumpTypeKey, int]:
        """Returns the type and offset of direct base classes for the given class."""
        self._expect_leaf(type_key, "LF_CLASS", "LF_STRUCTURE")

        return dict(self._field_list(type_key).get("super", {}))

    def class_info(self, type_key: CvdumpTypeKey) -> ClassInfo:
        """Returns class-specific information for the given class."""
        self._expect_leaf(type_key, "LF_CLASS", "LF_STRUCTURE")

        field_list = self._field_list(type_key)
        vbase = field_list.get("vbase")
        return ClassInfo(
            has_vftable=field_list.get("has_vftable", False),
            vbptr_offset=vbase.vboffset if vbase is not None else None,
            virtual_bases=list(vbase.bases) if vbase is not None else [],
        )

    def enum_variants(self, type_key: CvdumpTypeKey) -> list[EnumItem]:
        """Returns all variants for the given enum type."""
        self._expect_leaf(type_key, "LF_ENUM")

        return list(self._field_list(type_key).get("variants", []))

    def function(self, type_key: CvdumpTypeKey) -> FunctionInfo:
        """Returns function-specific information for this function type."""
        leaf = self._expect_leaf(type_key, "LF_PROCEDURE", "LF_MFUNCTION")

        arg_list = self.from_key(leaf["arg_list_type"])
        args = arg_list.get("args", [])
        assert arg_list["argcount"] == len(args)

        return FunctionInfo(
            call_type=leaf["call_type"],
            return_type=leaf["return_type"],
            args=args,
            class_type=leaf.get("class_type"),
            this_adjust=leaf.get("this_adjust", 0),
        )

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
