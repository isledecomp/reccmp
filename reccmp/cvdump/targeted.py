"""Conservative selection of cvdump module-symbol streams."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePath, PureWindowsPath
from typing import Iterable

from reccmp.formats import Image

from .parser import CvdumpParser, ModuleEntry


@dataclass(frozen=True)
class ModuleSelection:
    module_ids: frozenset[int]
    requires_full_symbols: bool = False


@dataclass(frozen=True)
class SymbolModuleHint:
    source_file: PurePath
    lookup_name: str | None = None


def _module_source_parts(module: ModuleEntry) -> tuple[str, ...]:
    raw_path = module.obj or module.lib
    if not raw_path:
        return ()
    if raw_path.lower().endswith(".obj"):
        raw_path = raw_path[:-4]
    return tuple(part.lower() for part in PureWindowsPath(raw_path).parts)


def _suffix_score(source: PurePath, module: ModuleEntry) -> int:
    source_parts = tuple(part.lower() for part in source.parts)
    module_parts = _module_source_parts(module)
    score = 0
    for source_part, module_part in zip(reversed(source_parts), reversed(module_parts)):
        if source_part != module_part:
            break
        score += 1
    return score


def select_modules(
    parser: CvdumpParser,
    recomp_bin: Image,
    symbol_hints: Iterable[SymbolModuleHint],
    recomp_addresses: Iterable[int],
    *,
    max_modules: int = 32,
) -> ModuleSelection:
    """Select symbol modules for known source files and recompiled addresses.

    A line-referenced annotation is associated with its source object. A
    name-referenced annotation is associated through GLOBALS/PROCREF or PUBLICS
    because its source file need not own the emitted symbol. Any unresolved known
    annotation requests the complete SYMBOLS stream. Unknown address filters are
    ignored so callers may query both image address spaces at once.
    """
    selected: set[int] = set()

    contribution_locations: dict[tuple[int, int], set[int]] = {}
    for entry in parser.sizerefs:
        contribution_locations.setdefault((entry.section, entry.offset), set()).add(
            entry.module
        )

    proc_ref_modules: dict[str, set[int]] = {}
    for proc_ref in parser.proc_refs:
        proc_ref_modules.setdefault(proc_ref.name, set()).add(proc_ref.module)

    public_modules: dict[str, set[int]] = {}
    for public in parser.publics:
        modules = contribution_locations.get((public.section, public.offset))
        if modules:
            public_modules.setdefault(public.name, set()).update(modules)

    for hint in set(symbol_hints):
        if hint.lookup_name is not None:
            name_modules = (
                public_modules.get(hint.lookup_name)
                if hint.lookup_name.startswith("?")
                else proc_ref_modules.get(hint.lookup_name)
            )
            if not name_modules:
                return ModuleSelection(frozenset(), requires_full_symbols=True)
            selected.update(name_modules)
            continue

        scored = [
            (_suffix_score(hint.source_file, module), module.id)
            for module in parser.modules
        ]
        top_score = max((score for score, _ in scored), default=0)
        if top_score == 0:
            return ModuleSelection(frozenset(), requires_full_symbols=True)
        selected.update(module_id for score, module_id in scored if score == top_score)

    contributions: dict[int, list[tuple[int, int, int]]] = {}
    for entry in parser.sizerefs:
        contributions.setdefault(entry.section, []).append(
            (entry.offset, entry.offset + entry.size, entry.module)
        )

    for address in set(recomp_addresses):
        try:
            section, offset = recomp_bin.get_relative_addr(address)
        except (IndexError, ValueError):
            continue
        address_modules = {
            module_id
            for start, end, module_id in contributions.get(section, ())
            if start <= offset < end
        }
        if not address_modules:
            return ModuleSelection(frozenset(), requires_full_symbols=True)
        selected.update(address_modules)

    if len(selected) > max_modules:
        return ModuleSelection(frozenset(), requires_full_symbols=True)
    return ModuleSelection(frozenset(selected))


def merge_module_symbols(target: CvdumpParser, source: CvdumpParser) -> None:
    """Merge one module-only SYMBOLS parse into a base cvdump parse."""
    target.symbols_parser.symbols.extend(source.symbols_parser.symbols)
    target.symbols_parser.alerted_types.update(source.symbols_parser.alerted_types)
    for line in source.symbols_parser.unhandled_lines:
        if line not in target.symbols_parser.unhandled_lines:
            target.symbols_parser.unhandled_lines.append(line)
