from typing import Iterable, NamedTuple
from reccmp.isledecomp.types import EntityType
from .db import EntityDb


class OverloadedFunctionEntity(NamedTuple):
    orig_addr: int | None
    recomp_addr: int | None
    name: str
    symbol: str | None
    # The number for this repeated name, starting at 1, ordered by orig_addr (nulls last), then recomp_addr.
    nth: int


def get_overloaded_functions(db: EntityDb) -> Iterable[OverloadedFunctionEntity]:
    """Find each function that has a non-unique name shared with other function entities.
    Uses a SQL window function to get the number for the repeated name so the caller
    doesn't need to keep track. We assume that a better name can be derived from
    the entity's symbol so we return that too."""
    for orig_addr, recomp_addr, name, symbol, nth in db.sql.execute(
        """SELECT orig_addr, recomp_addr,
        json_extract(kvstore,'$.name') as name,
        json_extract(kvstore,'$.symbol'),
        Row_number() OVER (partition BY json_extract(kvstore,'$.name') ORDER BY orig_addr nulls last, recomp_addr)
        from entities where json_extract(kvstore,'$.type') = ?
            and name in (
            select json_extract(kvstore,'$.name') as name from entities
            where json_extract(kvstore,'$.type') = ?
            and name is not null
            and ref_orig is null and ref_recomp is null
            group by name having count(name) > 1
        )
        and ref_orig is null and ref_recomp is null
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

    orig_addr: int | None
    recomp_addr: int | None
    name: str


def get_thunks_and_name(db: EntityDb):
    """For each entity with a ref_orig or ref_recomp attribute,
    if the parent entity is a function, return:
        - one or both addresses
        - the name (or computed name) of the parent entity"""
    for orig_addr, recomp_addr, name in db.sql.execute(
        """SELECT e.orig_addr, e.recomp_addr,
        coalesce(json_extract(r.kvstore, '$.computed_name'), json_extract(r.kvstore, '$.name')) name
        FROM entities e
        INNER JOIN entities r
        ON e.ref_orig = r.orig_addr or e.ref_recomp = r.recomp_addr
        WHERE name is not null
        -- Do not return rows where (for example) orig_addr and ref_recomp are set.
        -- If the entity has both ref_orig and ref_recomp, they must point to the same (matched) entity.
        AND (e.orig_addr is null and e.ref_orig is null or e.ref_orig = r.orig_addr)
        AND (e.recomp_addr is null and e.ref_recomp is null or e.ref_recomp = r.recomp_addr)
        AND json_extract(r.kvstore, '$.type') = ?
    """,
        (EntityType.FUNCTION,),
    ):
        assert isinstance(orig_addr, int) or isinstance(recomp_addr, int)
        assert isinstance(name, str)
        yield ThunkWithName(orig_addr, recomp_addr, name)
