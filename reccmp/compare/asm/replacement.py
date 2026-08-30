from functools import cache
from typing import Callable, Protocol
from reccmp.compare.db import EntityDb, ReccmpEntity
from reccmp.cvdump.types import CvdumpTypeKey
from reccmp.types import EntityType, ImageId

# Bounds for cross-side operand candidates. See create_candidate_lookup.
# A reference may point slightly before an entity (e.g. array base biased
# by the first index) or up to one-past-the-end plus a small field offset
# (e.g. the end bound of an array of structs, anchored on a struct member).
CANDIDATE_REACH_BEFORE = 16
CANDIDATE_SLACK_AFTER = 4

# How far back (in bytes) to scan for entities that could contain the
# search address. This must cover interior references into large entities
# (data arrays, structs).
CANDIDATE_SCAN_BACK = 0x2000


class AddrTestProtocol(Protocol):
    def __call__(self, addr: int, /) -> bool: ...


class NameReplacementProtocol(Protocol):
    def __call__(
        self, addr: int, exact: bool = False, indirect: bool = False
    ) -> str | None: ...


class CandidateLookupProtocol(Protocol):
    def __call__(self, addr: int, /) -> frozenset[tuple[int, int]]: ...


def create_candidate_lookup(db: EntityDb, image_id: ImageId) -> CandidateLookupProtocol:
    """Function generator for cross-side operand equivalence candidates.

    The returned lookup describes an address as the set of plausible
    interpretations (entity, delta): every *matched* entity nearby whose
    address range -- widened by a small tolerance -- covers the search
    address. Each candidate is expressed as (entity orig addr, delta) so
    that the same interpretation resolves to the same key in both images.

    Two operand addresses, one per image, refer to the same thing
    structurally if some interpretation is shared by both sides: the same
    matched entity at the same delta. The caller must intersect the
    candidate sets of both sides; a candidate on its own proves nothing.
    This symmetry requirement is what makes the wider tolerances safe:
    a one-sided resolution of "entity + slack" is never accepted."""
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    # A code entity is a unit: a reference just before or just past it
    # does not relate to it. Only its exact address and its interior
    # (e.g. embedded jump tables) can anchor a reference.
    code_types = frozenset(
        {
            EntityType.FUNCTION,
            EntityType.THUNK,
            EntityType.VTORDISP,
            EntityType.IMPORT_THUNK,
        }
    )

    # Variables, by contrast, are covered with a small tolerance before
    # the start and past the end, since a reference may be biased by an
    # array index or by a struct member offset.
    # Only entities that occupy bytes in the binary can anchor a
    # reference at all: passenger types (LINE, LABEL) and imports are
    # excluded.
    data_types = frozenset(
        (EntityType.solid_types() | {EntityType.OFFSET, EntityType.POINTER})
        - code_types
    )

    @cache
    def lookup(addr: int) -> frozenset[tuple[int, int]]:
        candidates = set()

        scan = range(addr - CANDIDATE_SCAN_BACK, addr + CANDIDATE_REACH_BEFORE + 1)
        for entity in db.all_in_range(image_id, scan):
            if not entity.matched:
                continue

            entity_type = entity.entity_type
            base_addr = entity.addr(image_id)
            assert base_addr is not None
            delta = addr - base_addr

            size = entity.any_size(image_id)
            if entity_type in data_types:
                in_range = (
                    -CANDIDATE_REACH_BEFORE <= delta <= size + CANDIDATE_SLACK_AFTER
                )
            elif entity_type in code_types:
                in_range = 0 <= delta < max(size, 1)
            else:
                continue

            if in_range:
                # The entity is matched so orig_addr is set.
                assert entity.orig_addr is not None
                candidates.add((entity.orig_addr, delta))

        return frozenset(candidates)

    return lookup


def create_name_lookup(
    db: EntityDb,
    image_id: ImageId,
    bin_read: Callable[[int], int | None],
    offset_name: Callable[[CvdumpTypeKey, int], str],
) -> NameReplacementProtocol:
    """Function generator for name replacement"""
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    def follow_indirect(pointer: int) -> ReccmpEntity | None:
        """Read the pointer address and open the entity (if it exists) at the indirect location."""
        addr = bin_read(pointer)
        if addr is not None:
            return db.get(image_id, addr, exact=True)

        return None

    def get_name(entity: ReccmpEntity, offset: int = 0) -> str | None:
        """The offset is the difference between the input search address and the entity's
        starting address. Decide whether to return the base name (match_name) or
        a string with the base name plus the offset.
        Returns None if there is no suitable name."""
        if offset == 0:
            return entity.match_name()

        # We will not return an offset name if this is not a variable
        # or if the offset is outside the range of the entity.
        # Exception: an offset exactly one past the end of the entity is
        # allowed, so we can identify one-past-the-end pointers (a common
        # compiler idiom for array end bounds). This case can only be reached
        # when no other entity starts at the given address.
        size = entity.any_size(image_id)
        if (
            entity.entity_type
            not in (
                EntityType.DATA,
                EntityType.OFFSET,
            )
            or offset > size
        ):
            return None

        if offset == size:
            # One-past-the-end reference: a common compiler idiom for the end
            # bound of an array. Only allow this for arrays and structs; for
            # a scalar an address just past the entity is much more likely to
            # be an unrelated (unannotated) neighbor variable.
            # Without type information, fall back to a size heuristic.
            type_key = entity.get("data_type")
            if (
                CvdumpTypeKey(type_key).is_scalar()
                if type_key is not None
                else size < 8
            ):
                return None
            # Skip the data_type offset lookup (the offset is outside the
            # type) and use the raw offset suffix.
            return entity.match_name(f"+{offset}")

        type_key = entity.get("data_type")
        if type_key:
            suffix = offset_name(CvdumpTypeKey(type_key), offset)
            return entity.match_name(suffix)

        return entity.match_name(f"+{offset}")

    def indirect_lookup(addr: int) -> str | None:
        """Same as regular lookup but aware of the fact that the address is a pointer.
        Indirect implies exact search, so we drop both parameters from the lookup entry point.
        """
        entity = db.get(image_id, addr, exact=True)
        if entity is not None:
            # If the indirect call points at a variable initialized to a function,
            # prefer the variable name as this is more useful.
            if entity.entity_type == EntityType.DATA:
                return entity.match_name()

            if entity.entity_type == EntityType.IMPORT:
                import_name = entity.match_name()
                if import_name is not None:
                    return "->" + import_name

                # If there's no name for the import, don't bother going further.
                # The pointer is a dead end.
                return None

        # No suitable entity at the base address. Read the pointer and see what we get.
        entity = follow_indirect(addr)

        if entity is None:
            return None

        # Exact match only for indirect.
        # The 'addr' variable still points at the indirect addr.
        name = get_name(entity, offset=0)
        if name is not None:
            return "->" + name

        return None

    @cache
    def lookup(addr: int, exact: bool = False, indirect: bool = False) -> str | None:
        """Returns the name that represents the entity at the given address.
        If there is no suitable name, return None and let the caller choose one (i.e. placeholder).
        * exact:    If the addr is an offset of an entity (e.g. struct/array) we may return
                    a name like 'variable+8'. If exact is True, return a name only if the entity's addr
                    matches the addr parameter.
        * indirect: If True, the given addr is a pointer so we have the option to read the address
                    from the binary to find the name."""
        if indirect:
            return indirect_lookup(addr)

        entity = db.get(image_id, addr, exact=exact)

        if entity is None:
            return None

        base_addr = entity.addr(image_id)
        assert base_addr is not None
        offset = addr - base_addr
        return get_name(entity, offset)

    return lookup
