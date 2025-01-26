"""Wrapper for database (here an in-memory sqlite database) that collects the
addresses/symbols that we want to compare between the original and recompiled binaries."""

import sqlite3
import logging
import json
from functools import cached_property
from typing import Any, Iterable, Iterator
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.cvdump.demangler import get_vtordisp_name

_SETUP_SQL = """
    CREATE TABLE entities (
        orig_addr int unique,
        recomp_addr int unique,
        matched int as (orig_addr is not null and recomp_addr is not null),
        kvstore text default '{}'
    );
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


class EntityDb:
    # pylint: disable=too-many-public-methods
    def __init__(self):
        self._sql = sqlite3.connect(":memory:")
        self._sql.executescript(_SETUP_SQL)
        self._indexed = set()

    @property
    def sql(self) -> sqlite3.Connection:
        return self._sql

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
        self._sql.executemany(
            "UPDATE or ignore entities SET orig_addr = ? WHERE recomp_addr = ?", pairs
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
            "SELECT orig_addr, recomp_addr, kvstore FROM entities ORDER BY orig_addr NULLS LAST"
        )
        cur.row_factory = entity_factory
        yield from cur

    def get_matches(self) -> Iterator[ReccmpMatch]:
        cur = self._sql.execute(
            """SELECT orig_addr, recomp_addr, kvstore FROM entities
            WHERE matched = 1
            ORDER BY orig_addr NULLS LAST
            """,
        )
        cur.row_factory = matched_entity_factory
        yield from cur

    def get_one_match(self, addr: int) -> ReccmpMatch | None:
        cur = self._sql.execute(
            """SELECT orig_addr, recomp_addr, kvstore FROM entities
            WHERE orig_addr = ?
            AND recomp_addr IS NOT NULL
            """,
            (addr,),
        )
        cur.row_factory = matched_entity_factory
        return cur.fetchone()

    def _get_closest_orig(self, addr: int) -> int | None:
        for (value,) in self._sql.execute(
            "SELECT orig_addr FROM entities WHERE ? >= orig_addr ORDER BY orig_addr desc LIMIT 1",
            (addr,),
        ):
            return value

        return None

    def _get_closest_recomp(self, addr: int) -> int | None:
        for (value,) in self._sql.execute(
            "SELECT recomp_addr FROM entities WHERE ? >= recomp_addr ORDER BY recomp_addr desc LIMIT 1",
            (addr,),
        ):
            return value

        return None

    def get_by_orig(self, orig: int, exact: bool = True) -> ReccmpEntity | None:
        addr = self._get_closest_orig(orig)
        if addr is None or exact and orig != addr:
            return None

        cur = self._sql.execute(
            "SELECT orig_addr, recomp_addr, kvstore FROM entities WHERE orig_addr = ?",
            (addr,),
        )
        cur.row_factory = entity_factory
        return cur.fetchone()

    def get_by_recomp(self, recomp: int, exact: bool = True) -> ReccmpEntity | None:
        addr = self._get_closest_recomp(recomp)
        if addr is None or exact and recomp != addr:
            return None

        cur = self._sql.execute(
            "SELECT orig_addr, recomp_addr, kvstore FROM entities WHERE recomp_addr = ?",
            (addr,),
        )
        cur.row_factory = entity_factory
        return cur.fetchone()

    def get_matches_by_type(self, entity_type: EntityType) -> Iterator[ReccmpMatch]:
        cur = self._sql.execute(
            """SELECT orig_addr, recomp_addr, kvstore FROM entities
            WHERE json_extract(kvstore, '$.type') = ?
            AND matched = 1
            ORDER BY orig_addr NULLS LAST
            """,
            (entity_type,),
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

    def set_pair_tentative(
        self, orig: int, recomp: int, entity_type: EntityType | None = None
    ) -> bool:
        """Declare a match for the original and recomp addresses given, but only if:
        1. The original address is not used elsewhere (as with set_pair)
        2. The recomp address has not already been matched
        If the entity_type is given, update this also, but only if NULL in the db.

        The purpose here is to set matches found via some automated analysis
        but to not overwrite a match provided by the human operator."""
        if self._orig_used(orig):
            # Probable and expected situation. Just ignore it.
            return False

        cur = self._sql.execute(
            """UPDATE entities
            SET orig_addr = ?, kvstore = json_insert(kvstore,'$.type',?)
            WHERE recomp_addr = ?
            AND orig_addr IS NULL""",
            (orig, entity_type, recomp),
        )

        return cur.rowcount > 0

    def set_function_pair(self, orig: int, recomp: int) -> bool:
        """For lineref match or _entry"""
        return self.set_pair(orig, recomp, EntityType.FUNCTION)

    def set_function_pair_tentative(self, orig: int, recomp: int) -> bool:
        """For lineref match or _entry"""
        return self.set_pair_tentative(orig, recomp, EntityType.FUNCTION)

    def create_orig_thunk(self, addr: int, name: str) -> bool:
        """Create a thunk function reference using the orig address.
        We are here because we have a match on the thunked function,
        but it is not thunked in the recomp build."""

        if self._orig_used(addr):
            return False

        thunk_name = f"Thunk of '{name}'"

        # Assuming relative jump instruction for thunks (5 bytes)
        cur = self._sql.execute(
            """INSERT INTO entities (orig_addr, kvstore)
            VALUES (:addr, json_insert('{}', '$.type', :type, '$.name', :name, '$.size', :size))""",
            {"addr": addr, "type": EntityType.FUNCTION, "name": thunk_name, "size": 5},
        )

        return cur.rowcount > 0

    def create_recomp_thunk(self, addr: int, name: str) -> bool:
        """Create a thunk function reference using the recomp address.
        We start from the recomp side for this because we are guaranteed
        to have full information from the PDB. We can use a regular function
        match later to pull in the orig address."""

        if self._recomp_used(addr):
            return False

        thunk_name = f"Thunk of '{name}'"

        # Assuming relative jump instruction for thunks (5 bytes)
        cur = self._sql.execute(
            """INSERT INTO entities (recomp_addr, kvstore)
            VALUES (:addr, json_insert('{}', '$.type', :type, '$.name', :name, '$.size', :size))""",
            {"addr": addr, "type": EntityType.FUNCTION, "name": thunk_name, "size": 5},
        )

        return cur.rowcount > 0

    def _set_opt_bool(self, addr: int, option: str, enabled: bool = True):
        self._sql.execute(
            "UPDATE entities SET kvstore = json_patch(kvstore,?) where orig_addr = ?",
            (json.dumps({option: enabled}), addr),
        )

    def mark_stub(self, orig: int):
        self._set_opt_bool(orig, "stub")

    def skip_compare(self, orig: int):
        self._set_opt_bool(orig, "skip")

    def is_vtordisp(self, recomp_addr: int) -> bool:
        """Check whether this function is a vtordisp based on its
        decorated name. If its demangled name is missing the vtordisp
        indicator, correct that."""
        row = self._sql.execute(
            """SELECT json_extract(kvstore,'$.name'), json_extract(kvstore,'$.symbol')
            FROM entities
            WHERE recomp_addr = ?""",
            (recomp_addr,),
        ).fetchone()

        if row is None:
            return False

        (name, decorated_name) = row
        if "`vtordisp" in name:
            return True

        if decorated_name is None:
            # happens in debug builds, e.g. for "Thunk of 'LegoAnimActor::ClassName'"
            return False

        new_name = get_vtordisp_name(decorated_name)
        if new_name is None:
            return False

        self._sql.execute(
            """UPDATE entities
            SET kvstore = json_set(kvstore, '$.name', ?)
            WHERE recomp_addr = ?""",
            (new_name, recomp_addr),
        )

        return True

    def search_symbol(self, symbol: str) -> Iterator[ReccmpEntity]:
        if "symbol" not in self._indexed:
            self._sql.execute(
                "CREATE index idx_symbol on entities(json_extract(kvstore, '$.symbol'))"
            )
            self._indexed.add("symbol")

        cur = self._sql.execute(
            """SELECT orig_addr, recomp_addr, kvstore FROM entities
            WHERE json_extract(kvstore, '$.symbol') = ?""",
            (symbol,),
        )
        cur.row_factory = entity_factory
        yield from cur

    def search_name(self, name: str, entity_type: EntityType) -> Iterator[ReccmpEntity]:
        if "name" not in self._indexed:
            self._sql.execute(
                "CREATE index idx_name on entities(json_extract(kvstore, '$.name'))"
            )
            self._indexed.add("name")

        # n.b. If the name matches and the type is not set, we will return the row.
        # Ideally we would have perfect information on the recomp side and not need to do this
        cur = self._sql.execute(
            """SELECT orig_addr, recomp_addr, kvstore FROM entities
            WHERE json_extract(kvstore, '$.name') = ?
            AND (json_extract(kvstore, '$.type') IS NULL OR json_extract(kvstore, '$.type') = ?)""",
            (name, entity_type),
        )
        cur.row_factory = entity_factory
        yield from cur

    def _match_on(self, entity_type: EntityType, addr: int, name: str) -> bool:
        """Search the program listing for the given name and type, then assign the
        given address to the first unmatched result."""
        # If we identify the name as a linker symbol, search for that instead.
        # TODO: Will need a customizable "name_is_symbol" function for other platforms
        if entity_type != EntityType.STRING and name.startswith("?"):
            for obj in self.search_symbol(name):
                if obj.orig_addr is None and obj.recomp_addr is not None:
                    return self.set_pair(addr, obj.recomp_addr, entity_type)

            return False

        # Truncate the name to 255 characters. It will not be possible to match a name
        # longer than that because MSVC truncates to this length.
        # See also: warning C4786.
        name = name[:255]

        for obj in self.search_name(name, entity_type):
            if obj.orig_addr is None and obj.recomp_addr is not None:
                matched = self.set_pair(addr, obj.recomp_addr, entity_type)

                # Type field has been set by set_pair, so we can use it in our count query:
                (count,) = self._sql.execute(
                    """SELECT count(rowid) from entities
                    where json_extract(kvstore,'$.name') = ?
                    AND json_extract(kvstore,'$.type') = ?""",
                    (name, entity_type),
                ).fetchone()

                if matched and count > 1:
                    logger.warning(
                        "Ambiguous match 0x%x on name '%s' to '%s'",
                        addr,
                        name,
                        obj.get("symbol"),
                    )

                return matched

        return False

    def get_next_orig_addr(self, addr: int) -> int | None:
        """Return the original address (matched or not) that follows
        the one given. If our recomp function size would cause us to read
        too many bytes for the original function, we can adjust it."""
        result = self._sql.execute(
            """SELECT orig_addr
            FROM entities
            WHERE orig_addr > ?
            ORDER BY orig_addr
            LIMIT 1""",
            (addr,),
        ).fetchone()

        return result[0] if result is not None else None

    def match_function(self, addr: int, name: str) -> bool:
        did_match = self._match_on(EntityType.FUNCTION, addr, name)
        if not did_match:
            logger.error(
                "Failed to find function symbol with annotation 0x%x and name '%s'",
                addr,
                name,
            )

        return did_match

    def match_vtable(
        self, addr: int, class_name: str, base_class: str | None = None
    ) -> bool:
        """Match the vtable for the given class name. If a base class is provided,
        we will match the multiple inheritance vtable instead.

        As with other name-based searches, set the given address on the first unmatched result.

        Our search here depends on having already demangled the vtable symbol before
        loading the data. For example: we want to search for "Pizza::`vftable'"
        so we extract the class name from its symbol "??_7Pizza@@6B@".

        For multiple inheritance, the vtable name references the base class like this:

            - X::`vftable'{for `Y'}

        The vtable for the derived class will take one of these forms:

            - X::`vftable'{for `X'}
            - X::`vftable'

        We assume only one of the above will appear for a given class."""
        # Most classes will not use multiple inheritance, so try the regular vtable
        # first, unless a base class is provided.
        if base_class is None or base_class == class_name:
            bare_vftable = f"{class_name}::`vftable'"

            for obj in self.search_name(bare_vftable, EntityType.VTABLE):
                if obj.orig_addr is None and obj.recomp_addr is not None:
                    return self.set_pair(addr, obj.recomp_addr, EntityType.VTABLE)

        # If we didn't find a match above, search for the multiple inheritance vtable.
        for_name = base_class if base_class is not None else class_name
        for_vftable = f"{class_name}::`vftable'{{for `{for_name}'}}"

        for obj in self.search_name(for_vftable, EntityType.VTABLE):
            if obj.orig_addr is None and obj.recomp_addr is not None:
                return self.set_pair(addr, obj.recomp_addr, EntityType.VTABLE)

        logger.error(
            "Failed to find vtable for class with annotation 0x%x and name '%s'",
            addr,
            class_name,
        )
        return False

    def match_static_variable(
        self, addr: int, variable_name: str, function_addr: int
    ) -> bool:
        """Matching a static function variable by combining the variable name
        with the decorated (mangled) name of its parent function."""

        result = self._sql.execute(
            "SELECT json_extract(kvstore, '$.name'), json_extract(kvstore, '$.symbol') FROM entities WHERE orig_addr = ?",
            (function_addr,),
        ).fetchone()

        if result is None:
            logger.error("No function for static variable: %s", variable_name)
            return False

        # Get the friendly name for the "failed to match" error message
        (function_name, function_symbol) = result

        # If the static variable has a symbol, it will contain the parent function's symbol.
        # e.g. Static variable "g_startupDelay" from function "IsleApp::Tick"
        # The function symbol is:                    "?Tick@IsleApp@@QAEXH@Z"
        # The variable symbol is: "?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA"
        for (recomp_addr,) in self._sql.execute(
            """SELECT recomp_addr FROM entities
            WHERE orig_addr IS NULL
            AND (json_extract(kvstore, '$.type') = ? OR json_extract(kvstore, '$.type') IS NULL)
            AND json_extract(kvstore, '$.symbol') LIKE '%' || ? || '%' || ? || '%'""",
            (EntityType.DATA, variable_name, function_symbol),
        ):
            return self.set_pair(addr, recomp_addr, EntityType.DATA)

        logger.error(
            "Failed to match static variable %s from function %s annotated with 0x%x",
            variable_name,
            function_name,
            addr,
        )

        return False

    def match_variable(self, addr: int, name: str) -> bool:
        did_match = self._match_on(EntityType.DATA, addr, name) or self._match_on(
            EntityType.POINTER, addr, name
        )
        if not did_match:
            logger.error("Failed to find variable annotated with 0x%x: %s", addr, name)

        return did_match

    def match_string(self, addr: int, value: str) -> bool:
        did_match = self._match_on(EntityType.STRING, addr, value)
        if not did_match:
            already_present = self.get_by_orig(addr, exact=True)
            escaped = repr(value)

            if already_present is None:
                logger.error(
                    "Failed to find string annotated with 0x%x: %s", addr, escaped
                )
            elif (
                already_present.entity_type == EntityType.STRING
                and already_present.name == value
            ):
                logger.debug(
                    "String annotated with 0x%x is annotated multiple times: %s",
                    addr,
                    escaped,
                )
            else:
                logger.error(
                    "Multiple annotations of 0x%x disagree: %s (STRING) vs. %s (%s)",
                    addr,
                    escaped,
                    repr(already_present.name),
                    repr(EntityType(already_present.entity_type))
                    if already_present.entity_type is not None
                    else "<None>",
                )

        return did_match
