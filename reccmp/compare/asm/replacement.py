from functools import cache
from typing import Callable, Protocol
from reccmp.compare.db import EntityDb, ReccmpEntity
from reccmp.types import EntityType, ImageId


class AddrTestProtocol(Protocol):
    def __call__(self, addr: int, /) -> bool: ...


class NameReplacementProtocol(Protocol):
    def __call__(
        self, addr: int, exact: bool = False, indirect: bool = False
    ) -> str | None: ...


def create_name_lookup(
    db: EntityDb,
    image_id: ImageId,
    bin_read: Callable[[int], int | None],
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
        if entity.entity_type not in (
            EntityType.DATA,
            EntityType.OFFSET,
        ) or offset >= entity.any_size(image_id):
            return None

        return entity.offset_name(offset)

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
