from typing import Iterable, NamedTuple
from reccmp.isledecomp.types import EntityType
from .db import EntityDb


class OverloadedFunctionEntity(NamedTuple):
    orig_addr: int | None
    recomp_addr: int | None
    name: str
    symbol: str | None
    # The number for this repeated name, starting at 1, ordered by orig_addr (nulls last), then recomp_addr.
    sequence: int


def get_overloaded_functions(db: EntityDb) -> Iterable[OverloadedFunctionEntity]:
    """Find each function that has a non-unique name shared with other function entities.
    Uses a SQL window function to get the number for the repeated name so the caller
    doesn't need to keep track. We assume that a better name can be derived from
    the entity's symbol so we return that too."""
    for orig_addr, recomp_addr, name, symbol, sequence in db.sql.execute(
        """SELECT orig_addr, recomp_addr,
        json_extract(kvstore,'$.name') as name,
        json_extract(kvstore,'$.symbol'),
        Row_number() OVER (partition BY json_extract(kvstore,'$.name') ORDER BY orig_addr nulls last, recomp_addr)
        from entities where json_extract(kvstore,'$.type') = ?
            and name in (
            select json_extract(kvstore,'$.name') as name from entities
            where json_extract(kvstore,'$.type') = ?
            and name is not null
            group by name having count(name) > 1
        )""",
        (EntityType.FUNCTION, EntityType.FUNCTION),
    ):
        assert isinstance(orig_addr, int) or isinstance(recomp_addr, int)
        assert isinstance(name, str)
        assert isinstance(symbol, str) or symbol is None
        assert isinstance(sequence, int)
        yield OverloadedFunctionEntity(orig_addr, recomp_addr, name, symbol, sequence)
