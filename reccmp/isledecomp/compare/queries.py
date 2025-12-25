from typing import Iterator, NamedTuple
from reccmp.isledecomp.types import EntityType, ImageId
from .db import EntityDb


class OverloadedFunctionEntity(NamedTuple):
    orig_addr: int | None
    recomp_addr: int | None
    name: str
    symbol: str | None
    # The number for this repeated name, starting at 1, ordered by orig_addr (nulls last), then recomp_addr.
    nth: int


def get_overloaded_functions(db: EntityDb) -> Iterator[OverloadedFunctionEntity]:
    """Find each function that has a non-unique name shared with other function entities.
    Uses a SQL window function to get the number for the repeated name so the caller
    doesn't need to keep track. We assume that a better name can be derived from
    the entity's symbol so we return that too."""
    for orig_addr, recomp_addr, name, symbol, nth in db.sql.execute(
        """SELECT orig_addr, recomp_addr,
        json_extract(kvstore,'$.name') AS name,
        json_extract(kvstore,'$.symbol'),
        row_number() OVER (PARTITION BY json_extract(kvstore,'$.name') ORDER BY orig_addr NULLS LAST, recomp_addr)
        FROM entities WHERE json_extract(kvstore,'$.type') = ?
            AND name IN (
            -- Subquery: build a list of names that are
            -- repeated among FUNCTION entities.
            SELECT json_extract(kvstore,'$.name') AS name FROM entities
            WHERE json_extract(kvstore,'$.type') = ?
            AND name IS NOT NULL
            GROUP by name HAVING COUNT(name) > 1
        )
        """,
        (EntityType.FUNCTION, EntityType.FUNCTION),
    ):
        assert isinstance(orig_addr, int) or isinstance(recomp_addr, int)
        assert isinstance(name, str)
        assert isinstance(symbol, str) or symbol is None
        assert isinstance(nth, int)
        yield OverloadedFunctionEntity(orig_addr, recomp_addr, name, symbol, nth)


class ThunkWithName(NamedTuple):
    """Entity address(es) and the name (computed or base name)
    of the referenced (thunked) entity."""

    img_id: ImageId
    addr: int
    name: str


def get_named_thunks(db: EntityDb) -> Iterator[ThunkWithName]:
    """Return a modified name to set for each thunk and vtordisp entity.
    The name is copied from the parent function entity.
    Must run db.populate_names_table() and db,propagate_thunk_names() first."""
    for img, addr, type_, name, disp0, disp1 in db.sql.execute(
        """SELECT n.img, n.addr, json_extract(e.kvstore, '$.type') type, coalesce(n.computed_name, n.name) name, r.disp0, r.disp1
        FROM names n
        INNER JOIN refs r
            ON n.img = r.img AND n.addr = r.addr
        INNER JOIN entities e
            ON (r.img = 0 AND r.addr = e.orig_addr)
            OR (r.img = 1 AND r.addr = e.recomp_addr)
        -- Rename thunk and vtordisp entities only.
        WHERE type IN (?, ?, ?)
        AND name IS NOT NULL
        -- Performance: we only need to yield one addr for a matched entity.
        GROUP BY e.rowid""",
        (EntityType.THUNK, EntityType.VTORDISP, EntityType.IMPORT_THUNK),
    ):
        assert img in (ImageId.ORIG, ImageId.RECOMP)
        assert isinstance(addr, int)
        assert isinstance(name, str)

        if type_ == EntityType.THUNK:
            yield ThunkWithName(img, addr, f"Thunk of '{name}'")
        elif type_ == EntityType.VTORDISP:
            yield ThunkWithName(img, addr, f"{name}`vtordisp{{{disp0}, {disp1}}}'")
        else:
            # Copy the name only
            yield ThunkWithName(img, addr, name)


def get_floats_without_data(
    db: EntityDb, image_id: ImageId
) -> Iterator[tuple[int, bool]]:
    """For each partially-created float entity (without data) in the given address space,
    return the address and whether it has double precision."""
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    for orig_addr, recomp_addr, size in db.sql.execute(
        """SELECT orig_addr, recomp_addr, json_extract(kvstore,'$.size') size
        FROM entities
        WHERE json_extract(kvstore,'$.type') = ?
        AND size in (4, 8)
        -- TODO: #27. We are using the name field to store the data for now,
        -- but we should put this data in its own table.
        AND json_extract(kvstore,'$.name') IS NULL
        """,
        (EntityType.FLOAT,),
    ):
        if image_id == ImageId.ORIG and isinstance(orig_addr, int):
            yield (orig_addr, size == 8)
        elif image_id == ImageId.RECOMP and isinstance(recomp_addr, int):
            yield (recomp_addr, size == 8)


def get_strings_without_data(
    db: EntityDb, image_id: ImageId
) -> Iterator[tuple[int, int | None, bool]]:
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    for orig_addr, recomp_addr, size, type_ in db.sql.execute(
        """SELECT orig_addr, recomp_addr, json_extract(kvstore,'$.size') size, json_extract(kvstore,'$.type') type
        FROM entities
        WHERE type IN (?, ?)
        -- TODO: #27. We are using the name field to store the data for now,
        -- but we should put this data in its own table.
        AND json_extract(kvstore,'$.name') IS NULL
        """,
        (EntityType.STRING, EntityType.WIDECHAR),
    ):

        if image_id == ImageId.ORIG and isinstance(orig_addr, int):
            yield (orig_addr, size, type_ == EntityType.WIDECHAR)
        elif image_id == ImageId.RECOMP and isinstance(recomp_addr, int):
            yield (recomp_addr, size, type_ == EntityType.WIDECHAR)


def get_referencing_entity_matches(db: EntityDb) -> Iterator[tuple[int, int]]:
    """Return new matches for child entities that refer to the same parent entity.
    These can be import thunks, incremental build thunks, or vtordisps.
    To match, the child entities must have the same displacement values (or none).
    If we cannot match uniquely, match by child address order in each address space.
    """
    for orig_addr, recomp_addr in db.sql.execute(
        """
        WITH linked_refs AS (
            SELECT r.img, r.addr, m.match_id, disp0, disp1,
            row_number() OVER (PARTITION BY r.img, m.match_id, disp0, disp1 ORDER BY r.addr) nth
            FROM refs r
            -- Convert the referenced address to a unique ID to allow for matching.
            INNER JOIN matches m
                ON (r.img = 0 AND r.ref = m.orig_addr)
                OR (r.img = 1 AND r.ref = m.recomp_addr)
            -- Exclude thunk entities that have been matched.
            INNER JOIN (
                SELECT img, addr FROM refs
                EXCEPT
                SELECT img, addr FROM matched_ids
            ) x
            ON r.img = x.img AND r.addr = x.addr
        )
        SELECT x.addr, y.addr FROM
        (SELECT * FROM linked_refs WHERE img = 0) x
        INNER JOIN
        (SELECT * FROM linked_refs WHERE img = 1) y
        ON  x.disp0 = y.disp0
        AND x.disp1 = y.disp1
        AND x.nth = y.nth
        AND x.match_id = y.match_id
        """
    ):
        assert isinstance(orig_addr, int)
        assert isinstance(recomp_addr, int)
        yield (orig_addr, recomp_addr)
