from functools import cache
from typing import Callable, Protocol
from reccmp.isledecomp.compare.db import ReccmpEntity
from reccmp.isledecomp.types import SymbolType


class AddrTestProtocol(Protocol):
    def __call__(self, addr: int, /) -> bool:
        ...


class NameReplacementProtocol(Protocol):
    def __call__(self, addr: int, exact: bool = False) -> str | None:
        ...


def create_name_lookup(
    db_getter: Callable[[int, bool], ReccmpEntity | None], addr_attribute: str
) -> NameReplacementProtocol:
    """Function generator for name replacement"""

    @cache
    def lookup(addr: int, exact: bool = False) -> str | None:
        m = db_getter(addr, exact)
        if m is None:
            return None

        if getattr(m, addr_attribute) == addr:
            return m.match_name()

        offset = addr - getattr(m, addr_attribute)
        if m.compare_type != SymbolType.DATA or offset >= m.size:
            return None

        return m.offset_name(offset)

    return lookup
