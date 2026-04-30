"""Wrapper for database (here an in-memory sqlite database) that collects the
addresses/symbols that we want to compare between the original and recompiled binaries.
"""

import bisect
import logging
from typing import Any, Iterable, Iterator
from reccmp.types import EntityType, ImageId


def entity_name_from_string(text: str, wide: bool = False) -> str:
    """Create an entity name for the given string by escaping
    control characters and double quotes, then wrapping in double quotes."""
    escaped = text.encode("unicode_escape").decode("utf-8").replace('"', '\\"')
    return f'{"L" if wide else ""}"{escaped}"'


EntityTypeLookup: dict[int, str] = {
    value: name for name, value in EntityType.__members__.items()
}


class ReccmpEntity:
    """ORM object for Reccmp database entries."""

    _orig_addr: int | None
    _recomp_addr: int | None
    _kvstore: dict[str, Any]

    def __init__(
        self,
        orig: int | None,
        recomp: int | None,
        kvstore: dict[str, Any] | None = None,
    ) -> None:
        """Requires one or both of the addresses to be defined"""
        assert orig is not None or recomp is not None
        self._orig_addr = orig
        self._recomp_addr = recomp
        if kvstore:
            self._kvstore = kvstore
        else:
            self._kvstore = {}

    def addr(self, image_id: ImageId) -> int | None:
        if image_id == ImageId.ORIG:
            return self._orig_addr

        if image_id == ImageId.RECOMP:
            return self._recomp_addr

        assert False, "Invalid image id"

    @property
    def orig_addr(self) -> int | None:
        return self._orig_addr

    @property
    def recomp_addr(self) -> int | None:
        return self._recomp_addr

    @property
    def entity_type(self) -> int | None:
        return self._kvstore.get("type")

    @property
    def name(self) -> str | None:
        return self._kvstore.get("name")

    def any_size(self, image_id: ImageId = ImageId.RECOMP) -> int:
        """Returns any size for this entity: the returned value cannot be null.
        Prefer to return the size attribute for the provided ImageId if it exists.
        With no ImageId, prefer recomp_size first, then orig_size, default to zero.
        (This matches the previous behavior.)"""
        if image_id == ImageId.RECOMP:
            return (
                self._kvstore.get("recomp_size") or self._kvstore.get("orig_size") or 0
            )

        if image_id == ImageId.ORIG:
            return (
                self._kvstore.get("orig_size") or self._kvstore.get("recomp_size") or 0
            )

        return 0

    def size(self, image_id: ImageId) -> int | None:
        """Return the size attribute for the provided ImageId."""
        if image_id == ImageId.ORIG:
            return self._kvstore.get("orig_size")

        if image_id == ImageId.RECOMP:
            return self._kvstore.get("recomp_size")

        assert False, "Invalid image id"

    @property
    def matched(self) -> bool:
        return self._orig_addr is not None and self._recomp_addr is not None

    def get(self, key: str, default: Any = None) -> Any:
        return self._kvstore.get(key, default)

    def best_name(self) -> str | None:
        """Return the first name that exists from our
        priority list of name attributes for this entity."""
        for key in ("computed_name", "name"):
            if (value := self._kvstore.get(key)) is not None:
                return str(value)

        return None

    def match_name(self) -> str | None:
        """Combination of the name and compare type.
        Intended for name substitution in the diff. If there is a diff,
        it will be more obvious what this symbol indicates."""
        best_name = self.best_name()
        if best_name is None:
            return None

        ctype = EntityTypeLookup.get(self.entity_type or -1, "UNK")
        return f"{best_name} ({ctype})"

    def offset_name(self, ofs: int) -> str | None:
        if self.name is None:
            return None

        return f"{self.name}+{ofs} (OFFSET)"


class ReccmpMatch(ReccmpEntity):
    """To simplify type checking, use this object when a "match" is
    required or expected. Meaning: both orig and recomp addresses are set."""

    def __init__(
        self, orig: int, recomp: int, kvstore: dict[str, Any] | None = None
    ) -> None:
        assert orig is not None and recomp is not None
        super().__init__(orig, recomp, kvstore)

    @property
    def orig_addr(self) -> int:
        assert self._orig_addr is not None
        return self._orig_addr

    @property
    def recomp_addr(self) -> int:
        assert self._recomp_addr is not None
        return self._recomp_addr


logger = logging.getLogger(__name__)


# pylint: disable=too-many-instance-attributes
class EntityBatch:
    base: "EntityDb"

    _orig: dict[int, dict[str, Any]]
    _recomp: dict[int, dict[str, Any]]
    _matches: list[tuple[int, int]]

    def __init__(self, backref: "EntityDb") -> None:
        self.base = backref
        self._orig = {}
        self._recomp = {}
        self._matches = []

    def reset(self):
        """Clear all pending changes"""
        self._orig.clear()
        self._recomp.clear()
        self._matches.clear()

    def set(
        self,
        img: ImageId,
        addr: int,
        ref: int | None = None,
        size: int | None = None,
        **kwargs,
    ):
        assert img in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

        if ref is not None:
            kwargs["ref_orig" if img == ImageId.ORIG else "ref_recomp"] = ref

        if size is not None:
            kwargs["orig_size" if img == ImageId.ORIG else "recomp_size"] = size

        if img == ImageId.ORIG:
            self._orig.setdefault(addr, {}).update(kwargs)

        elif img == ImageId.RECOMP:
            self._recomp.setdefault(addr, {}).update(kwargs)

    def set_ref(
        self,
        img: ImageId,
        addr: int,
        *,
        ref: int,
        displacement: tuple[int, int] = (0, 0),
    ):
        self.set(img, addr, ref=ref, displacement=displacement)

    def match(self, orig: int, recomp: int):
        self._matches.append((orig, recomp))

    def set_recomp_addr(self, orig: int, recomp: int):
        self.match(orig, recomp)

    def _finalized_matches(self) -> Iterator[tuple[int, int]]:
        """Reduce the list of matches so that each orig and recomp addr appears once.
        If an address is repeated, retain the first pair where it is used and ignore any others.
        """
        used_orig = set()
        used_recomp = set()

        # This should have the same effect as the original implementation
        # that used two dicts to check uniqueness during each call to match().
        for orig, recomp in self._matches:
            if orig not in used_orig and recomp not in used_recomp:
                used_orig.add(orig)
                used_recomp.add(recomp)
                yield ((orig, recomp))
            else:
                logger.warning(
                    "Match (%x, %x) collides with previous staged match", orig, recomp
                )

    def commit(self):
        if self._orig:
            self.base.bulk_insert(ImageId.ORIG, self._orig.items())

        if self._recomp:
            self.base.bulk_insert(ImageId.RECOMP, self._recomp.items())

        if self._matches:
            self.base.bulk_match(self._finalized_matches())

        self.reset()

    def __enter__(self) -> "EntityBatch":
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type is not None:
            self.reset()
        else:
            self.commit()


class EntityDb:
    # pylint: disable=too-many-public-methods
    _entities: dict[ImageId, dict[int, ReccmpEntity]]
    _matches: dict[ImageId, dict[int, int]]
    _addr_set: dict[ImageId, set[int]]
    _addr_order: dict[ImageId, list[int]]

    def __init__(self):
        self._entities = {ImageId.ORIG: {}, ImageId.RECOMP: {}}
        self._matches = {ImageId.ORIG: {}, ImageId.RECOMP: {}}

        self._addr_set = {ImageId.ORIG: set(), ImageId.RECOMP: set()}
        self._addr_order = {ImageId.ORIG: [], ImageId.RECOMP: []}

    def batch(self) -> EntityBatch:
        return EntityBatch(self)

    def count(self) -> int:
        return len(list(self.get_all()))

    def _update_addr_index(self, img: ImageId, addrs: set[int]):
        """Update the ordered list of addresses in this address space."""
        extent = self._addr_set[img]
        order = self._addr_order[img]
        order.extend(addrs - extent)
        order.sort()
        extent |= addrs

    def bulk_insert(self, image: ImageId, rows: Iterable[tuple[int, dict[str, Any]]]):
        assert image in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"
        new_addrs = set()
        entities = self._entities[image]

        for addr, values in rows:
            new_addrs.add(addr)

            if addr not in entities:
                if image == ImageId.ORIG:
                    entities[addr] = ReccmpEntity(addr, None, values)
                else:
                    entities[addr] = ReccmpEntity(None, addr, values)
            else:
                entities[addr]._kvstore.update(
                    values
                )  # pylint: disable=protected-access

        self._update_addr_index(image, new_addrs)

    def bulk_match(self, pairs: Iterable[tuple[int, int]]):
        """Expects iterable of `(orig_addr, recomp_addr)`."""

        orig_entities = self._entities[ImageId.ORIG]
        recomp_entities = self._entities[ImageId.RECOMP]

        new_x = set()
        new_y = set()

        for x, y in pairs:
            # Cannot replace existing match.
            if x in self._matches[ImageId.ORIG] or y in self._matches[ImageId.RECOMP]:
                continue

            new_x.add(x)
            new_y.add(y)

            self._matches[ImageId.ORIG][x] = y
            self._matches[ImageId.RECOMP][y] = x

            orig_data = {}
            if x in orig_entities:
                # pylint: disable=protected-access
                orig_data = orig_entities[x]._kvstore

            recomp_data = {}
            if y in recomp_entities:
                # Remove null values from recomp. If we don't, the merge
                # will overwrite a value at the same key in orig.
                # pylint: disable=protected-access
                recomp_data = {
                    k: v
                    for k, v in recomp_entities[y]._kvstore.items()
                    if v is not None
                }

            match = ReccmpMatch(x, y, orig_data | recomp_data)

            orig_entities[x] = match
            recomp_entities[y] = match

        self._update_addr_index(ImageId.ORIG, new_x)
        self._update_addr_index(ImageId.RECOMP, new_y)

    def all(self, img: ImageId) -> Iterator[ReccmpEntity]:
        """Iterate entities in order for the given the address space."""
        assert img in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

        entities = self._entities[img]

        for addr in self._addr_order[img]:
            if addr in entities:
                yield entities[addr]

    def unmatched(self, img: ImageId) -> Iterator[ReccmpEntity]:
        """Iterate unmatched entities only in order for the given the address space."""
        assert img in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

        entities = self._entities[img]
        matches = self._matches[img]

        for addr in self._addr_order[img]:
            if addr in entities and addr not in matches:
                yield entities[addr]

    def get_all(self) -> Iterator[ReccmpEntity]:
        orig_entities = self._entities[ImageId.ORIG]
        recomp_entities = self._entities[ImageId.RECOMP]

        for orig_addr in self._addr_order[ImageId.ORIG]:
            yield orig_entities[orig_addr]

        for recomp_addr in self._addr_order[ImageId.RECOMP]:
            if recomp_addr not in self._matches[ImageId.RECOMP]:
                yield recomp_entities[recomp_addr]

    def get_matches(self) -> Iterator[ReccmpMatch]:
        matches = self._matches[ImageId.ORIG]
        entities = self._entities[ImageId.ORIG]
        for orig_addr in self._addr_order[ImageId.ORIG]:
            if orig_addr in matches:
                ent = entities[orig_addr]
                assert isinstance(ent, ReccmpMatch)
                yield ent

    def get_one_match(self, orig_addr: int) -> ReccmpMatch | None:
        if orig_addr not in self._entities[ImageId.ORIG]:
            return None

        ent = self._entities[ImageId.ORIG][orig_addr]
        if ent.recomp_addr is None:
            return None

        assert isinstance(ent, ReccmpMatch)
        return ent

    def nearest(self, img: ImageId, addr: int) -> int | None:
        assert img in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"
        addrs = self._addr_order[img]

        i = bisect.bisect_right(addrs, addr)
        if i == 0:
            return None

        return addrs[i - 1]

    def get(
        self, img: ImageId, addr: int, *, exact: bool = True
    ) -> ReccmpEntity | None:
        """Return the ReccmpEntity at the given address and address space (ImageId).
        If there is no entry for the address and exact=True (default), return None.
        Otherwise, return the preceding (by address, in this image) entity if it exists.
        The caller should check the entity's size to make sure it covers the address."""
        assert img in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

        if not exact and addr not in self._entities[img]:
            prev_addr = self.nearest(img, addr)
            if prev_addr is None:
                return None

            addr = prev_addr

        return self._entities[img].get(addr)

    def get_functions(self) -> Iterator[ReccmpMatch]:
        """Return all function-like matched entities. Previously, all functions
        had type=FUNCTION but there are now THUNK and VTORDISP types."""
        for ent in self.get_matches():
            if ent.get("type") in (
                EntityType.FUNCTION,
                EntityType.THUNK,
                EntityType.VTORDISP,
            ):
                yield ent

    def get_matches_by_type(self, entity_type: EntityType) -> Iterator[ReccmpMatch]:
        for ent in self.get_matches():
            if ent.get("type") == entity_type:
                yield ent

    def get_lines_in_recomp_range(
        self, start_recomp_addr: int, end_recomp_addr: int
    ) -> Iterator[ReccmpMatch]:
        """Fetches all matched annotations of the form `// LINE: TARGET 0x1234` in the given recomp address range."""
        addrs = self._addr_order[ImageId.RECOMP]
        i = bisect.bisect_left(addrs, start_recomp_addr)
        j = bisect.bisect_right(addrs, end_recomp_addr)

        recomp_matches = self._matches[ImageId.RECOMP]
        candidates = addrs[i:j]
        orig_addrs = [
            recomp_matches[addr] for addr in candidates if addr in recomp_matches
        ]

        for orig_addr in sorted(orig_addrs):
            match = self._entities[ImageId.ORIG][orig_addr]
            if match.get("type") == EntityType.LINE:
                assert isinstance(match, ReccmpMatch)
                yield match

    def used(self, img: ImageId, addr: int) -> bool:
        assert img in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"
        return addr in self._addr_set[img]

    def is_match(self, orig_addr: int, recomp_addr: int) -> bool:
        return self._matches[ImageId.ORIG].get(orig_addr) == recomp_addr

    def get_next_orig_addr(self, addr: int) -> int | None:
        """Return the original address (matched or not) that follows
        the one given. If our recomp function size would cause us to read
        too many bytes for the original function, we can adjust it.
        Skips LINE and LABEL type entities since these these are always contained
        within functions.
        """
        addrs = self._addr_order[ImageId.ORIG]
        i = bisect.bisect_left(addrs, addr)
        for next_addr in addrs[i:]:
            ent = self._entities[ImageId.ORIG][next_addr]

            if (
                next_addr > addr
                and ent
                and ent.get("type")
                and ent.get("type") not in (EntityType.LINE, EntityType.LABEL)
            ):
                return next_addr

        return None
