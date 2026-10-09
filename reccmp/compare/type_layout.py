"""Functions that return the layout of a struct according to our requirements.
These are intended to work with any implementation of a type database."""

from typing import Iterator
from reccmp.cvdump.cvinfo import CvdumpTypeKey, CvdumpTypeMap, CVInfoTypeEnum
from reccmp.cvdump.types import (
    CvdumpKeyError,
    CvdumpTypesParser,
    FieldListItem,
    TypeKind,
)


def join_member_names(parent: str, child: str) -> str:
    """Helper method to combine parent/child member names."""

    # If one of the strings is empty, return the one we have.
    # (Done for convenience. Expanding embedded base class structs does not add a parent.)
    if not parent or not child:
        return parent or child

    # If the child is an array index, join without the dot
    if child.startswith("["):
        return f"{parent}{child}"

    return f"{parent}.{child}"


def disjoint_members(
    types: CvdumpTypesParser, key: CvdumpTypeKey
) -> list[FieldListItem]:
    """Returns members of a struct or union sorted by offset with overlap members removed.
    A struct that contains an anonymous (inline) union will have overlapping members, so this
    processing is needed for any situation where the caller needs a cohesive list.
    If two members overlap at the same offset, choose the member with the largest footprint.
    """
    members = types.members(key)
    sizes = [types.get(m.type).size or 0 for m in members]

    order = sorted(range(len(members)), key=lambda i: (members[i].offset, -sizes[i]))

    kept: list[FieldListItem] = []
    next_offset = 0
    for i in order:
        if members[i].offset >= next_offset:
            kept.append(members[i])
            next_offset = members[i].offset + sizes[i]

    return kept


def composite_layout(
    types: CvdumpTypesParser, key: CvdumpTypeKey
) -> list[FieldListItem]:
    """Returns members of a struct with members from direct base classes inserted.
    If the class has a vftable, we add a mock member at offset 0.
    This is intended for `datacmp` comparison. The Ghidra import should use disjoint_members().
    For simplicity, this function will handle union types, but because no inheritance is possible,
    no members are added."""
    if types.get(key).kind == TypeKind.UNION:
        return disjoint_members(types, key)

    items: list[FieldListItem] = [
        FieldListItem(offset=base_offset, name="", type=base)
        for base, base_offset in types.base_classes(key).items()
    ]
    if types.class_info(key).has_vftable:
        # TODO: Assumes 32-bit pointers. (GH #573)
        items.append(
            FieldListItem(offset=0, type=CVInfoTypeEnum.T_32PVOID, name="vftable")
        )

    items += disjoint_members(types, key)
    items.sort(key=lambda item: item.offset)
    return items


def get_scalars(
    types: CvdumpTypesParser, key: CvdumpTypeKey, offset: int = 0, name: str = ""
) -> Iterator[FieldListItem]:
    """Reduce the given complex type to a list of primitive member types."""
    t = types.get(key)
    match t.kind:
        case TypeKind.SCALAR:
            yield FieldListItem(offset, name, t.key)

        case TypeKind.POINTER:
            # TODO: Assumes 32-bit pointers. (GH #573)
            pointer = t.key if t.key.is_scalar() else CVInfoTypeEnum.T_32PVOID
            yield FieldListItem(offset, name, pointer)

        case TypeKind.ENUM | TypeKind.BITFIELD:
            yield from get_scalars(types, types.underlying_type(t.key), offset, name)

        case TypeKind.ARRAY:
            element = types.get(types.element_type(t.key))
            assert element.size, "Encountered an array whose type has no size"
            assert t.size is not None

            for i in range(t.size // element.size):
                yield from get_scalars(
                    types,
                    element.key,
                    offset + i * element.size,
                    join_member_names(name, f"[{i}]"),
                )

        case TypeKind.STRUCT | TypeKind.UNION:
            if t.size is None:
                raise CvdumpKeyError(f"Forward ref {t.key} has no target")

            for m in composite_layout(types, t.key):
                yield from get_scalars(
                    types, m.type, offset + m.offset, join_member_names(name, m.name)
                )


def _padding(start: int, end: int) -> Iterator[FieldListItem]:
    for i in range(start, end):
        yield FieldListItem(i, "", CVInfoTypeEnum.T_UCHAR)


def get_scalars_gapless(
    types: CvdumpTypesParser, key: CvdumpTypeKey
) -> list[FieldListItem]:
    """Reduce the given complex type to a list of primitive member types.
    Gaps between the declared members are filled with explicit padding bytes."""
    output: list[FieldListItem] = []
    next_offset = 0
    for scalar in get_scalars(types, key):
        output.extend(_padding(next_offset, scalar.offset))
        output.append(scalar)
        next_offset = scalar.offset + CvdumpTypeMap[scalar.type].size

    size = types.get(key).size
    assert size is not None
    output.extend(_padding(next_offset, size))
    return output


def get_format_string(scalars: list[FieldListItem]) -> str:
    """Create a struct.unpack format string from the list of primitive types.
    Gaps between the declared members are skipped using the 'x' character so
    that the alignment is correct."""
    parts: list[str] = []
    next_offset = 0
    for scalar in scalars:
        if scalar.offset > next_offset:
            parts.append(f"{scalar.offset - next_offset}x")
        parts.append(CvdumpTypeMap[scalar.type].fmt)
        next_offset = scalar.offset + CvdumpTypeMap[scalar.type].size

    format_string = "".join(parts)
    if len(format_string) > 0:
        return "<" + format_string

    return ""


def _item_at_offset(
    types: CvdumpTypesParser, key: CvdumpTypeKey, offset: int
) -> FieldListItem | None:
    """The base class or member at or closest before the given offset."""
    best = None
    for item in composite_layout(types, key):
        if item.offset > offset:
            break
        best = item

    return best


def get_name_for_offset(
    types: CvdumpTypesParser, type_key: CvdumpTypeKey, offset: int
) -> str:
    """Limited to arrays for now. Enable to close GH #462."""
    try:
        if types.get(type_key).kind != TypeKind.ARRAY:
            return f"+{offset}" if offset > 0 else ""
    except CvdumpKeyError:
        return f"+{offset}" if offset > 0 else ""

    names = []

    # 2 levels max depth (for now)
    depth = 0
    while depth < 2:
        try:
            t = types.get(type_key)
        except CvdumpKeyError:
            break

        if t.kind == TypeKind.ARRAY:
            element = types.get(types.element_type(t.key))
            assert element.size

            array_idx = offset // element.size
            type_key = element.key
            offset -= array_idx * element.size
            names.append(f"[{array_idx}]")
            depth += 1

        elif t.kind in (TypeKind.STRUCT, TypeKind.UNION):
            item = _item_at_offset(types, t.key, offset)
            if item is None:
                # Negative offset?
                break

            type_key = item.type
            offset -= item.offset

            # Descending into a base class does not add to the name.
            if item.name:
                names.append(f".{item.name}")
                depth += 1

        else:
            break

    if offset > 0:
        names.append(f"+{offset}")

    return "".join(names)
