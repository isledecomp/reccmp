"""Wrapper for database (here an in-memory sqlite database) that collects the
addresses/symbols that we want to compare between the original and recompiled binaries.
"""

import bisect
import logging
from functools import cached_property
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

    @cached_property
    def options(self) -> dict[str, Any]:
        return self._kvstore

    @property
    def orig_addr(self) -> int | None:
        return self._orig_addr

    @property
    def recomp_addr(self) -> int | None:
        return self._recomp_addr

    @property
    def entity_type(self) -> int | None:
        return self.options.get("type")

    @property
    def name(self) -> str | None:
        return self.options.get("name")

    def any_size(self, image_id: ImageId = ImageId.RECOMP) -> int:
        """Returns any size for this entity: the returned value cannot be null.
        Prefer to return the size attribute for the provided ImageId if it exists.
        With no ImageId, prefer recomp_size first, then orig_size, default to zero.
        (This matches the previous behavior.)"""
        if image_id == ImageId.RECOMP:
            return self.options.get("recomp_size") or self.options.get("orig_size") or 0

        if image_id == ImageId.ORIG:
            return self.options.get("orig_size") or self.options.get("recomp_size") or 0

        return 0

    def size(self, image_id: ImageId) -> int | None:
        """Return the size attribute for the provided ImageId."""
        if image_id == ImageId.ORIG:
            return self.options.get("orig_size")

        if image_id == ImageId.RECOMP:
            return self.options.get("recomp_size")

        assert False, "Invalid image id"

    @property
    def matched(self) -> bool:
        return self._orig_addr is not None and self._recomp_addr is not None

    def get(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)

    def best_name(self) -> str | None:
        """Return the first name that exists from our
        priority list of name attributes for this entity."""
        for key in ("computed_name", "name"):
            if (value := self.options.get(key)) is not None:
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
            self.base.bulk_orig_insert(self._orig.items())

        if self._recomp:
            self.base.bulk_recomp_insert(self._recomp.items())

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
    def __init__(self):
        self._x_orig = {}
        self._y_recomp = {}
        self._x_matches = {}
        self._y_matches = {}

        self._x_all = []
        self._y_all = []

    def batch(self) -> EntityBatch:
        return EntityBatch(self)

    def count(self) -> int:
        # TODO: if we care
        return len(list(self.get_all()))

    def _new_orig(self, addr: int):
        if addr not in self._x_orig and addr not in self._x_matches:
            bisect.insort(self._x_all, addr)

    def _new_recomp(self, addr: int):
        if addr not in self._y_recomp and addr not in self._y_matches:
            bisect.insort(self._y_all, addr)

    def bulk_orig_insert(self, rows: Iterable[tuple[int, dict[str, Any]]]):
        for addr, values in rows:
            self._new_orig(addr)

            if addr not in self._x_orig:
                self._x_orig[addr] = ReccmpEntity(addr, None)

            # pylint:disable=protected-access
            denoise = {k: v for k, v in values.items() if v is not None}
            self._x_orig[addr]._kvstore.update(denoise)

    def bulk_recomp_insert(self, rows: Iterable[tuple[int, dict[str, Any]]]):
        for addr, values in rows:
            self._new_recomp(addr)

            if addr not in self._y_recomp:
                self._y_recomp[addr] = ReccmpEntity(None, addr)

            # pylint:disable=protected-access
            denoise = {k: v for k, v in values.items() if v is not None}
            self._y_recomp[addr]._kvstore.update(denoise)

    def bulk_match(self, pairs: Iterable[tuple[int, int]]):
        """Expects iterable of `(orig_addr, recomp_addr)`."""

        for x, y in pairs:
            # Cannot replace existing match.
            if x in self._x_matches or y in self._y_matches:
                continue

            self._new_orig(x)
            self._new_recomp(y)

            self._x_matches[x] = y
            self._y_matches[y] = x

            orig_data = {}
            if x in self._x_orig:
                # pylint:disable=protected-access
                orig_data = self._x_orig[x]._kvstore

            recomp_data = {}
            if y in self._y_recomp:
                # pylint:disable=protected-access
                recomp_data = self._y_recomp[y]._kvstore

            match = ReccmpMatch(x, y, orig_data | recomp_data)

            self._x_orig[x] = match
            self._y_recomp[y] = match

    def all(self, img: ImageId) -> Iterator[ReccmpEntity]:
        if img == ImageId.ORIG:
            for addr in self._x_all:
                if addr in self._x_orig:
                    yield self._x_orig[addr]

        elif img == ImageId.RECOMP:
            for addr in self._y_all:
                if addr in self._y_recomp:
                    yield self._y_recomp[addr]

        else:
            assert False, "Invalid image id"

    def unmatched(self, img: ImageId) -> Iterator[ReccmpEntity]:
        if img == ImageId.ORIG:
            for addr in self._x_all:
                if addr in self._x_orig and addr not in self._x_matches:
                    yield self._x_orig[addr]

        elif img == ImageId.RECOMP:
            for addr in self._y_all:
                if addr in self._y_recomp and addr not in self._y_matches:
                    yield self._y_recomp[addr]

        else:
            assert False, "Invalid image id"

    def get_all(self) -> Iterator[ReccmpEntity]:
        for orig_addr in self._x_all:
            yield self._x_orig[orig_addr]

        for recomp_addr in self._y_all:
            if recomp_addr not in self._y_matches:
                yield self._y_recomp[recomp_addr]

    def get_matches(self) -> Iterator[ReccmpMatch]:
        for orig_addr in self._x_all:
            if orig_addr in self._x_matches:
                yield self._x_orig[orig_addr]

    def get_one_match(self, orig_addr: int) -> ReccmpMatch | None:
        if orig_addr not in self._x_orig:
            return None

        ent = self._x_orig[orig_addr]
        if ent.recomp_addr is None:
            return None

        return ent

    def nearest(self, img: ImageId, addr: int) -> int | None:
        if img == ImageId.ORIG:
            addrs = self._x_all
        elif img == ImageId.RECOMP:
            addrs = self._y_all
        else:
            assert False, "Invalid image id"

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
        if img == ImageId.ORIG:
            if not exact and addr not in self._x_orig:
                prev_addr = self.nearest(img, addr)
                if prev_addr is None:
                    return None

                addr = prev_addr

            return self._x_orig.get(addr)

        if img == ImageId.RECOMP:
            if not exact and addr not in self._y_recomp:
                prev_addr = self.nearest(img, addr)
                if prev_addr is None:
                    return None

                addr = prev_addr

            return self._y_recomp.get(addr)

        assert False, "Invalid image id"

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
        i = bisect.bisect_left(self._y_all, start_recomp_addr)
        j = bisect.bisect_right(self._y_all, end_recomp_addr)

        candidates = self._y_all[i:j]
        orig_addrs = [
            self._y_matches[addr] for addr in candidates if addr in self._y_matches
        ]

        for orig_addr in sorted(orig_addrs):
            match = self._x_orig[orig_addr]
            if match.get("type") == EntityType.LINE:
                yield match

    def used(self, img: ImageId, addr: int) -> bool:
        if img == ImageId.ORIG:
            return addr in self._x_orig or addr in self._x_matches

        if img == ImageId.RECOMP:
            return addr in self._y_recomp or addr in self._y_matches

        assert False, "Invalid image id"

    def is_match(self, orig_addr: int, recomp_addr: int) -> bool:
        return self._x_matches.get(orig_addr) == recomp_addr

    def get_next_orig_addr(self, addr: int) -> int | None:
        """Return the original address (matched or not) that follows
        the one given. If our recomp function size would cause us to read
        too many bytes for the original function, we can adjust it.
        Skips LINE and LABEL type entities since these these are always contained
        within functions.
        """
        i = bisect.bisect_left(self._x_all, addr)
        for next_addr in self._x_all[i:]:
            ent = self._x_orig[next_addr]

            if (
                next_addr > addr
                and ent
                and ent.get("type")
                and ent.get("type") not in (EntityType.LINE, EntityType.LABEL)
            ):
                return next_addr

        return None
