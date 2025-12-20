"""Wrapper for database (here an in-memory sqlite database) that collects the
addresses/symbols that we want to compare between the original and recompiled binaries.
"""

import sqlite3
import logging
import json
from functools import cached_property
from typing import Any, Iterable, Iterator
from reccmp.isledecomp.types import EntityType, ImageId

_SETUP_SQL = """
    CREATE TABLE names (
        img integer not null,
        addr integer not null,
        name text,
        computed_name text,
        primary key (img, addr)
    );

    CREATE TABLE entities (
        orig_addr int unique,
        recomp_addr int unique,
        kvstore text default '{}'
    );

    -- REFS stores the destination of the JMP instruction in each thunk/vtordisp.
    -- vtordisp functions have 1 or 2 displacement values that modify ECX.
    -- If both are zero, this is a regular thunk with the jump only.
    CREATE TABLE refs (
        img integer not null,
        addr integer not null,
        ref integer not null,
        disp0 integer not null default 0,
        disp1 integer not null default 0,
        primary key (img, addr)
    );

    CREATE VIEW matches (match_id, orig_addr, recomp_addr) AS
        SELECT rowid, orig_addr, recomp_addr FROM entities
        WHERE orig_addr IS NOT NULL AND recomp_addr IS NOT NULL;

    CREATE VIEW matched_ids (img, addr) AS
        SELECT 0, orig_addr FROM matches
        UNION ALL
        SELECT 1, recomp_addr FROM matches;

    CREATE VIEW orig_unmatched (orig_addr, kvstore) AS
        SELECT orig_addr, kvstore FROM entities
        WHERE orig_addr is not null and recomp_addr is null
        ORDER by orig_addr;

    CREATE VIEW recomp_unmatched (recomp_addr, kvstore) AS
        SELECT recomp_addr, kvstore FROM entities
        WHERE recomp_addr is not null and orig_addr is null
        ORDER by recomp_addr;

    -- ReccmpEntity
    CREATE VIEW entity_factory (orig_addr, recomp_addr, kvstore) AS
        SELECT orig_addr, recomp_addr, kvstore FROM entities;

    -- ReccmpMatch
    CREATE VIEW matched_entity_factory AS
        SELECT * FROM entity_factory WHERE orig_addr IS NOT NULL AND recomp_addr IS NOT NULL;
"""


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
    _kvstore: str

    def __init__(
        self, orig: int | None, recomp: int | None, kvstore: str = "{}"
    ) -> None:
        """Requires one or both of the addresses to be defined"""
        assert orig is not None or recomp is not None
        self._orig_addr = orig
        self._recomp_addr = recomp
        self._kvstore = kvstore

    @cached_property
    def options(self) -> dict[str, Any]:
        return json.loads(self._kvstore)

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

    @property
    def size(self) -> int:
        """Assume null size means size is zero: there are no bytes to read for this entity."""
        return self.options.get("size", 0)

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

    def __init__(self, orig: int, recomp: int, kvstore: str = "{}") -> None:
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


def entity_factory(_, row: object) -> ReccmpEntity:
    assert isinstance(row, tuple)
    return ReccmpEntity(*row)


def matched_entity_factory(_, row: object) -> ReccmpMatch:
    assert isinstance(row, tuple)
    return ReccmpMatch(*row)


logger = logging.getLogger(__name__)


# pylint: disable=too-many-instance-attributes
class EntityBatch:
    base: "EntityDb"

    _orig: dict[int, dict[str, Any]]
    _recomp: dict[int, dict[str, Any]]
    _matches: list[tuple[int, int]]

    # Sets the recomp_addr of an entity with only an orig_addr.
    # This isn't possible using set_orig() or by matching.
    _recomp_addr: dict[int, int]

    _refs: list[tuple[ImageId, int, int, int, int]]

    def __init__(self, backref: "EntityDb") -> None:
        self.base = backref
        self._orig = {}
        self._recomp = {}
        self._matches = []
        self._recomp_addr = {}
        self._refs = []

    def reset(self):
        """Clear all pending changes"""
        self._orig.clear()
        self._recomp.clear()
        self._matches.clear()
        self._recomp_addr.clear()
        self._refs.clear()

    def set_orig(self, addr: int, **kwargs):
        self._orig.setdefault(addr, {}).update(kwargs)

    def set_recomp(self, addr: int, **kwargs):
        self._recomp.setdefault(addr, {}).update(kwargs)

    def set(self, img: ImageId, addr: int, **kwargs):
        if img == ImageId.ORIG:
            self.set_orig(addr, **kwargs)

        elif img == ImageId.RECOMP:
            self.set_recomp(addr, **kwargs)

        else:
            assert False, "Invalid image id"

    def set_ref(
        self,
        img: ImageId,
        addr: int,
        *,
        ref: int,
        displacement: tuple[int, int] = (0, 0),
    ):
        self._refs.append((img, addr, ref, *displacement))

    def match(self, orig: int, recomp: int):
        self._matches.append((orig, recomp))

    def set_recomp_addr(self, orig: int, recomp: int):
        self._recomp_addr[orig] = recomp

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
        # SQL transaction
        with self.base.sql:
            if self._orig:
                self.base.bulk_orig_insert(self._orig.items(), upsert=True)

            if self._recomp:
                self.base.bulk_recomp_insert(self._recomp.items(), upsert=True)

            if self._refs:
                self.base.sql.executemany(
                    "INSERT OR REPLACE INTO refs (img, addr, ref, disp0, disp1) VALUES (?,?,?,?,?)",
                    self._refs,
                )

            if self._matches:
                self.base.bulk_match(self._finalized_matches())

            if self._recomp_addr:
                self.base.bulk_set_recomp_addr(self._recomp_addr.items())

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
        self._sql = sqlite3.connect(":memory:")
        self._sql.executescript(_SETUP_SQL)

    @property
    def sql(self) -> sqlite3.Connection:
        return self._sql

    def batch(self) -> EntityBatch:
        return EntityBatch(self)

    def count(self) -> int:
        (count,) = self._sql.execute("SELECT count(1) from entities").fetchone()
        return count

    def set_orig_symbol(self, addr: int, **kwargs):
        self.bulk_orig_insert(iter([(addr, kwargs)]))

    def set_recomp_symbol(self, addr: int, **kwargs):
        self.bulk_recomp_insert(iter([(addr, kwargs)]))

    def bulk_orig_insert(
        self, rows: Iterable[tuple[int, dict[str, Any]]], upsert: bool = False
    ):
        if upsert:
            self._sql.executemany(
                """INSERT INTO entities (orig_addr, kvstore) values (?,?)
                ON CONFLICT (orig_addr) DO UPDATE
                SET kvstore = json_patch(kvstore, excluded.kvstore)""",
                ((addr, json.dumps(values)) for addr, values in rows),
            )
        else:
            self._sql.executemany(
                "INSERT or ignore INTO entities (orig_addr, kvstore) values (?,?)",
                ((addr, json.dumps(values)) for addr, values in rows),
            )

    def bulk_recomp_insert(
        self, rows: Iterable[tuple[int, dict[str, Any]]], upsert: bool = False
    ):
        if upsert:
            self._sql.executemany(
                """INSERT INTO entities (recomp_addr, kvstore) values (?,?)
                ON CONFLICT (recomp_addr) DO UPDATE
                SET kvstore = json_patch(kvstore, excluded.kvstore)""",
                ((addr, json.dumps(values)) for addr, values in rows),
            )
        else:
            self._sql.executemany(
                "INSERT or ignore INTO entities (recomp_addr, kvstore) values (?,?)",
                ((addr, json.dumps(values)) for addr, values in rows),
            )

    def bulk_match(self, pairs: Iterable[tuple[int, int]]):
        """Expects iterable of `(orig_addr, recomp_addr)`."""
        # We need to iterate over this multiple times.
        pairlist = list(pairs)

        with self._sql:
            # Copy orig information to recomp side. Prefer recomp information except for NULLS.
            # json_patch(X, Y) copies keys from Y into X and replaces existing values.
            # From inner-most to outer-most:
            # - json_patch('{}', entities.kvstore)      Eliminate NULLS on recomp side (so orig will replace)
            # - json_patch(o.kvstore, ^)                Merge orig and recomp keys. Prefer recomp values.
            self._sql.executemany(
                """UPDATE entities
                SET kvstore = json_patch(o.kvstore, json_patch('{}', entities.kvstore))
                FROM (SELECT kvstore FROM entities WHERE orig_addr = ? and recomp_addr is null) o
                WHERE recomp_addr = ? AND orig_addr is null""",
                pairlist,
            )
            # Patch orig address into recomp and delete orig entry.
            self._sql.executemany(
                "UPDATE OR REPLACE entities SET orig_addr = ? WHERE recomp_addr = ? AND orig_addr is null",
                pairlist,
            )

    def bulk_set_recomp_addr(self, pairs: Iterable[tuple[int, int]]):
        """Expects iterable of `(orig_addr recomp_addr)`. To be used when the orig information are complete
        up to the recomp address and there exists no entry on the recomp side."""
        self._sql.executemany(
            """UPDATE entities
                SET recomp_addr = ?
                WHERE orig_addr = ? and recomp_addr is null""",
            ((recomp_addr, orig_addr) for orig_addr, recomp_addr in pairs),
        )

    def get_unmatched_strings(self) -> list[str]:
        """Return any strings not already identified by `STRING` markers."""

        cur = self._sql.execute(
            "SELECT json_extract(kvstore,'$.name') FROM entities WHERE json_extract(kvstore, '$.type') = ? AND orig_addr IS NULL",
            (EntityType.STRING,),
        )

        return [string for (string,) in cur.fetchall()]

    def get_all(self) -> Iterator[ReccmpEntity]:
        cur = self._sql.execute(
            "SELECT * FROM entity_factory ORDER BY orig_addr NULLS LAST, recomp_addr"
        )
        cur.row_factory = entity_factory
        yield from cur

    def get_matches(self) -> Iterator[ReccmpMatch]:
        cur = self._sql.execute(
            "SELECT * FROM matched_entity_factory ORDER BY orig_addr",
        )
        cur.row_factory = matched_entity_factory
        yield from cur

    def get_one_match(self, addr: int) -> ReccmpMatch | None:
        cur = self._sql.execute(
            "SELECT * FROM matched_entity_factory WHERE orig_addr = ?",
            (addr,),
        )
        cur.row_factory = matched_entity_factory
        return cur.fetchone()

    def get_by_orig(self, addr: int, *, exact: bool = True) -> ReccmpEntity | None:
        """Return the ReccmpEntity at the given orig address.
        If there is no entry for the address and exact=True (default), return None.
        Otherwise, return the entity at the preceding orig address if it exists.
        The caller should check the entity's size to make sure it covers the address."""
        if exact:
            query = "SELECT * FROM entity_factory WHERE orig_addr = ?"
        else:
            query = "SELECT * FROM entity_factory WHERE ? >= orig_addr ORDER BY orig_addr desc LIMIT 1"

        cur = self._sql.execute(query, (addr,))
        cur.row_factory = entity_factory
        return cur.fetchone()

    def get_by_recomp(self, addr: int, *, exact: bool = True) -> ReccmpEntity | None:
        """Return the ReccmpEntity at the given recomp address.
        If there is no entry for the address and exact=True (default), return None.
        Otherwise, return the entity at the preceding recomp address if it exists.
        The caller should check the entity's size to make sure it covers the address."""
        if exact:
            query = "SELECT * FROM entity_factory WHERE recomp_addr = ?"
        else:
            query = "SELECT * FROM entity_factory WHERE ? >= recomp_addr ORDER BY recomp_addr desc LIMIT 1"

        cur = self._sql.execute(query, (addr,))
        cur.row_factory = entity_factory
        return cur.fetchone()

    def get(
        self, img: ImageId, addr: int, *, exact: bool = True
    ) -> ReccmpEntity | None:
        if img == ImageId.ORIG:
            return self.get_by_orig(addr, exact=exact)

        if img == ImageId.RECOMP:
            return self.get_by_recomp(addr, exact=exact)

        assert False, "Invalid image id"

    def get_functions(self) -> Iterator[ReccmpMatch]:
        """Return all function-like matched entities. Previously, all functions
        had type=FUNCTION but there are now THUNK and VTORDISP types."""
        cur = self._sql.execute(
            """SELECT * FROM matched_entity_factory
            WHERE json_extract(kvstore, '$.type') IN (?, ?, ?)
            ORDER BY orig_addr
            """,
            (EntityType.FUNCTION, EntityType.THUNK, EntityType.VTORDISP),
        )
        cur.row_factory = matched_entity_factory
        yield from cur

    def get_matches_by_type(self, entity_type: EntityType) -> Iterator[ReccmpMatch]:
        cur = self._sql.execute(
            """SELECT * FROM matched_entity_factory
            WHERE json_extract(kvstore, '$.type') = ?
            ORDER BY orig_addr
            """,
            (entity_type,),
        )
        cur.row_factory = matched_entity_factory
        yield from cur

    def get_lines_in_recomp_range(
        self, start_recomp_addr: int, end_recomp_addr: int
    ) -> Iterator[ReccmpMatch]:
        """Fetches all matched annotations of the form `// LINE: TARGET 0x1234` in the given recomp address range."""

        cur = self._sql.execute(
            """SELECT * FROM matched_entity_factory
            WHERE json_extract(kvstore, '$.type') = ?
            AND recomp_addr >= ? AND recomp_addr <= ?
            ORDER BY orig_addr
            """,
            (
                EntityType.LINE,
                start_recomp_addr,
                end_recomp_addr,
            ),
        )
        cur.row_factory = matched_entity_factory
        yield from cur

    def orig_used(self, addr: int) -> bool:
        cur = self._sql.execute("SELECT 1 FROM entities WHERE orig_addr = ?", (addr,))
        return cur.fetchone() is not None

    def recomp_used(self, addr: int) -> bool:
        cur = self._sql.execute("SELECT 1 FROM entities WHERE recomp_addr = ?", (addr,))
        return cur.fetchone() is not None

    def used(self, img: ImageId, addr: int) -> bool:
        if img == ImageId.ORIG:
            return self.orig_used(addr)

        if img == ImageId.RECOMP:
            return self.recomp_used(addr)

        assert False, "Invalid image id"

    def set_pair(
        self, orig: int, recomp: int, entity_type: EntityType | None = None
    ) -> bool:
        if self.orig_used(orig):
            logger.debug("Original address %s not unique!", hex(orig))
            return False

        cur = self._sql.execute(
            "UPDATE entities SET orig_addr = ?, kvstore=json_set(kvstore,'$.type',?) WHERE recomp_addr = ?",
            (orig, entity_type, recomp),
        )

        return cur.rowcount > 0

    def get_next_orig_addr(self, addr: int) -> int | None:
        """Return the original address (matched or not) that follows
        the one given. If our recomp function size would cause us to read
        too many bytes for the original function, we can adjust it.
        Skips LINE-type symbols since these these are always contained
        within functions.
        """
        result = self._sql.execute(
            """SELECT orig_addr
            FROM entities
            WHERE
              orig_addr > ?
            AND
              json_extract(kvstore,'$.type') != ?
            ORDER BY orig_addr
            LIMIT 1""",
            (addr, EntityType.LINE),
        ).fetchone()

        return result[0] if result is not None else None

    def populate_names_table(self):
        """Copy the name/computed_name of non-thunk functions or imports into the NAMES table.
        NAMES is keyed by (image, addr), unlike the ENTITIES table."""
        self._sql.execute(
            """INSERT INTO names (img, addr, name, computed_name)
            SELECT img, addr, json_extract(kvstore, '$.name') name, json_extract(kvstore, '$.computed_name') FROM (
                SELECT 0 img, orig_addr addr, kvstore FROM entities WHERE orig_addr IS NOT NULL
                UNION ALL
                SELECT 1 img, recomp_addr addr, kvstore FROM entities WHERE recomp_addr IS NOT NULL
            )
            WHERE name IS NOT NULL
            AND json_extract(kvstore, '$.type') IN (?, ?)
            """,
            # These types are chosen because they are the possible sources for the name of a thunk function.
            (
                EntityType.FUNCTION,
                EntityType.IMPORT,
            ),
        )

    def propagate_thunk_names(self) -> bool:
        """Copy name/computed_name from parent to child (referencing) entities.
        Return value tells whether any entities were updated.
        Can be repeated to cover chains of thunk/vtordisp entities."""
        cur = self._sql.execute(
            """INSERT INTO names (img, addr, name, computed_name)
            SELECT r.img, r.addr, x.name, x.computed_name
            FROM refs r
            INNER JOIN names x ON r.img = x.img and r.ref = x.addr
            LEFT JOIN names y ON r.img = y.img and r.addr = y.addr
            WHERE y.addr IS NULL
            """
        )

        return cur.rowcount > 0
