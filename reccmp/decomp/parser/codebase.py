"""For aggregating decomp markers read from an entire directory and for a single module."""

from typing import Callable, Iterable, Iterator
from reccmp.decomp.formats import TextFile
from .parser import DecompParser
from .node import (
    ParserLineSymbol,
    ParserSymbol,
    ParserFunction,
    ParserVtable,
    ParserVariable,
    ParserString,
)


class DecompCodebase:
    def __init__(self, files: Iterable[TextFile], module: str) -> None:
        self._symbols: list[ParserSymbol] = []

        parser = DecompParser()
        for f in files:
            parser.reset_and_set_filename(f.path)
            parser.read(f.text)

            self._symbols += parser.iter_symbols(module)

    def prune_invalid_addrs(
        self, is_valid: Callable[[int], bool]
    ) -> list[ParserSymbol]:
        """Some decomp annotations might have an invalid address.
        Return the list of addresses where we fail the is_valid check,
        and remove those from our list of symbols."""
        invalid_symbols = [sym for sym in self._symbols if not is_valid(sym.offset)]
        self._symbols = [sym for sym in self._symbols if is_valid(sym.offset)]

        return invalid_symbols

    def prune_reused_addrs(self) -> list[ParserSymbol]:
        """We are focused on annotations for a single module, so each address should be used only once.
        Keep only the first occurrence of an address and discard the others.
        Return the duplicates in a list for error reporting."""
        used_addr = set()
        duplicates = []
        unique = []

        for s in self._symbols:
            if s.offset in used_addr:
                duplicates.append(s)
            else:
                unique.append(s)
                used_addr.add(s.offset)

        self._symbols = unique
        return duplicates

    def iter_line_functions(self) -> Iterator[ParserFunction]:
        """Return lineref functions separately from nameref. Assuming the PDB matches
        the state of the source code, a line reference is a guaranteed match, even if
        multiple functions share the same name. (i.e. polymorphism)"""
        return (
            s
            for s in self._symbols
            if isinstance(s, ParserFunction) and not s.is_nameref()
        )

    def iter_name_functions(self) -> Iterator[ParserFunction]:
        return (
            s for s in self._symbols if isinstance(s, ParserFunction) and s.is_nameref()
        )

    def iter_vtables(self) -> Iterator[ParserVtable]:
        return (s for s in self._symbols if isinstance(s, ParserVtable))

    def iter_variables(self) -> Iterator[ParserVariable]:
        return (s for s in self._symbols if isinstance(s, ParserVariable))

    def iter_strings(self) -> Iterator[ParserString]:
        return (s for s in self._symbols if isinstance(s, ParserString))

    def iter_line_symbols(self) -> Iterator[ParserLineSymbol]:
        return (s for s in self._symbols if isinstance(s, ParserLineSymbol))
