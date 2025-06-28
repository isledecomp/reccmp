"""Wrapper for database (here an in-memory sqlite database) that collects the
addresses/symbols that we want to compare between the original and recompiled binaries.
"""

import sqlite3
import logging
import json
from functools import cached_property
from typing import Any, Iterable, Iterator
from reccmp.isledecomp.types import EntityType

_SETUP_SQL = """
    CREATE TABLE entities (
        orig_addr int unique,
        recomp_addr int unique,
        kvstore text default '{}'
    );

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

        # Special handling for strings that might contain newlines.
        if self.entity_type == EntityType.STRING:
            if self.name is not None:
                # Escape newlines so they do not interfere
                # with asm sanitize and diff calculation.
                return f"{repr(self.name)} (STRING)"

            return None

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

    # To be inserted only if the address is unused
    _orig_insert: dict[int, dict[str, Any]]
    _recomp_insert: dict[int, dict[str, Any]]

    # To be upserted
    _orig: dict[int, dict[str, Any]]
    _recomp: dict[int, dict[str, Any]]

    # Matches
    _orig_to_recomp: dict[int, int]
    _recomp_to_orig: dict[int, int]

    # Set recomp address
    _recomp_addr: dict[int, int]

    def __init__(self, backref: "EntityDb") -> None:
        self.base = backref
        self._orig_insert = {}
        self._recomp_insert = {}
        self._orig = {}
        self._recomp = {}
        self._orig_to_recomp = {}
        self._recomp_to_orig = {}
        self._recomp_addr = {}

    def reset(self):
        """Clear all pending changes"""
        self._orig_insert.clear()
        self._recomp_insert.clear()
        self._orig.clear()
        self._recomp.clear()
        self._orig_to_recomp.clear()
        self._recomp_to_orig.clear()
        self._recomp_addr.clear()

    def insert_orig(self, addr: int, **kwargs):
        self._orig_insert.setdefault(addr, {}).update(kwargs)

    def insert_recomp(self, addr: int, **kwargs):
        self._recomp_insert.setdefault(addr, {}).update(kwargs)

    def set_orig(self, addr: int, **kwargs):
        self._orig.setdefault(addr, {}).update(kwargs)

    def set_recomp(self, addr: int, **kwargs):
        self._recomp.setdefault(addr, {}).update(kwargs)

    def match(self, orig: int, recomp: int):
        # Integrity check: orig and recomp addr must be used only once
        if (used_orig := self._recomp_to_orig.pop(recomp, None)) is not None:
            self._orig_to_recomp.pop(used_orig, None)

        self._orig_to_recomp[orig] = recomp
        self._recomp_to_orig[recomp] = orig

    def set_recomp_addr(self, orig: int, recomp: int):
        self._recomp_addr[orig] = recomp

    def commit(self):
        # SQL transaction
        with self.base.sql:
            if self._orig_insert:
                self.base.bulk_orig_insert(self._orig_insert.items())

            if self._recomp_insert:
                self.base.bulk_recomp_insert(self._recomp_insert.items())

            if self._orig:
                self.base.bulk_orig_insert(self._orig.items(), upsert=True)

            if self._recomp:
                self.base.bulk_recomp_insert(self._recomp.items(), upsert=True)

            if self._orig_to_recomp:
                self.base.bulk_match(self._orig_to_recomp.items())

            if self._recomp_addr:
                self.base.bulk_set_recomp_addr(self._recomp_addr.items())

        self.reset()

    def __enter__(self):
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

    def _orig_used(self, addr: int) -> bool:
        cur = self._sql.execute("SELECT 1 FROM entities WHERE orig_addr = ?", (addr,))
        return cur.fetchone() is not None

    def _recomp_used(self, addr: int) -> bool:
        cur = self._sql.execute("SELECT 1 FROM entities WHERE recomp_addr = ?", (addr,))
        return cur.fetchone() is not None

    def set_pair(
        self, orig: int, recomp: int, entity_type: EntityType | None = None
    ) -> bool:
        if self._orig_used(orig):
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
