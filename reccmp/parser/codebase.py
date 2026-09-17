"""For aggregating decomp markers read from an entire directory and for a single module."""

from pathlib import PurePath
from typing import Callable, Iterable, Iterator
from reccmp.formats import TextFile
from .marker import ProjectAliases
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
    def __init__(
        self,
        files: Iterable[TextFile],
        module: str,
        aliases: ProjectAliases | None = None,
    ) -> None:
        self._symbols: list[ParserSymbol] = []

        parser = DecompParser(aliases)
        for f in files:
            parser.reset_and_set_filename(f.path)
            parser.read(f.text)

            self._symbols += parser.iter_symbols(module.upper())

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
        Keep the first non-folded claim on an address as the owner. FOLDED claims on the same
        address are retained as aliases. A later non-folded claim that collides with an earlier
        FOLDED-only address replaces that FOLDED entry as the owner (the FOLDED marker stays).
        Return discarded duplicates in a list for error reporting."""
        used_addr: dict[int, ParserSymbol] = {}
        duplicates = []
        unique: list[ParserSymbol] = []

        for s in self._symbols:
            previous = used_addr.get(s.offset)
            if previous is None:
                unique.append(s)
                used_addr[s.offset] = s
                continue

            s_folded = isinstance(s, (ParserFunction, ParserVtable)) and s.is_folded
            prev_folded = (
                isinstance(previous, (ParserFunction, ParserVtable)) and previous.is_folded
            )

            if s_folded:
                # Additional FOLDED alias of an existing owner (or earlier FOLDED).
                unique.append(s)
                continue

            if prev_folded:
                # Promote this unfolded owner over the earlier FOLDED placeholder.
                used_addr[s.offset] = s
                unique.append(s)
                continue

            duplicates.append(s)

        self._symbols = unique
        return duplicates

    def files_for_offsets(self, offsets: Iterable[int]) -> dict[int, set[PurePath]]:
        """Return source files containing annotations at selected addresses."""
        return {
            offset: {symbol.filename for symbol in symbols}
            for offset, symbols in self.symbols_for_offsets(offsets).items()
        }

    def symbols_for_offsets(
        self, offsets: Iterable[int]
    ) -> dict[int, list[ParserSymbol]]:
        """Return annotations at selected addresses without mutating the codebase."""
        wanted = set(offsets)
        result: dict[int, list[ParserSymbol]] = {}
        for symbol in self._symbols:
            if symbol.offset in wanted:
                result.setdefault(symbol.offset, []).append(symbol)
        return result

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
