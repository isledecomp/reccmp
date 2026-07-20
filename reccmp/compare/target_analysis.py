"""Target loading, module-scoped PDB analysis, and validated setup caching."""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from pathlib import Path
from typing import Iterable

from reccmp.analysis_cache import (
    AnalysisCache,
    fingerprint_files,
    fingerprint_text_files,
)
from reccmp.cvdump import Cvdump, CvdumpAnalysis, CvdumpParser, CvdumpTypesParser
from reccmp.cvdump.targeted import (
    SymbolModuleHint,
    merge_module_symbols,
    select_modules,
)
from reccmp.dir import source_code_search
from reccmp.formats import Image, TextFile, detect_image
from reccmp.parser import DecompCodebase
from reccmp.parser.marker import ProjectAliases
from reccmp.project.detect import RecCmpTarget

from .db import EntityDb
from .lines import LinesDb

logger = logging.getLogger(__name__)

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_CVDUMP_CACHE_INPUTS = (
    _PACKAGE_ROOT / "cvdump" / "analysis.py",
    _PACKAGE_ROOT / "cvdump" / "parser.py",
    _PACKAGE_ROOT / "cvdump" / "runner.py",
    _PACKAGE_ROOT / "cvdump" / "symbols.py",
    _PACKAGE_ROOT / "cvdump" / "targeted.py",
    _PACKAGE_ROOT / "cvdump" / "types.py",
)
_MARKER_CACHE_INPUTS = (
    _PACKAGE_ROOT / "parser" / "codebase.py",
    _PACKAGE_ROOT / "parser" / "marker.py",
    _PACKAGE_ROOT / "parser" / "node.py",
    _PACKAGE_ROOT / "parser" / "parser.py",
)
_COMPARE_CACHE_INPUTS = tuple(
    sorted((_PACKAGE_ROOT / "compare").rglob("*.py"), key=str)
) + (
    _PACKAGE_ROOT / "analysis_cache.py",
    _PACKAGE_ROOT / "formats" / "image.py",
    _PACKAGE_ROOT / "formats" / "pe.py",
    _PACKAGE_ROOT / "types.py",
)


@dataclass
class PreparedAnalysis:
    db: EntityDb
    lines_db: LinesDb
    types: CvdumpTypesParser


@dataclass
class LoadedTargetAnalysis:
    # pylint: disable=too-many-instance-attributes
    orig_bin: Image
    recomp_bin: Image
    pdb_file: CvdumpAnalysis
    code_files: list[TextFile]
    data_sources: list[TextFile]
    project_aliases: ProjectAliases
    codebase: DecompCodebase
    cache: AnalysisCache
    prepared_cache_name: str
    prepared_fingerprint: str

    def load_prepared(self) -> PreparedAnalysis | None:
        return self.cache.load(self.prepared_cache_name, self.prepared_fingerprint)

    def store_prepared(self, prepared: PreparedAnalysis) -> None:
        self.cache.store(self.prepared_cache_name, self.prepared_fingerprint, prepared)


def _load_full_cvdump(
    pdb_path: Path, cache: AnalysisCache, fingerprint: str
) -> CvdumpParser:
    cached: CvdumpParser | None = cache.load("cvdump-full", fingerprint)
    if cached is not None:
        return cached
    parser = (
        Cvdump(str(pdb_path))
        .lines()
        .globals()
        .publics()
        .symbols()
        .section_contributions()
        .types()
        .run()
    )
    cache.store("cvdump-full", fingerprint, parser)
    return parser


def _load_base_cvdump(
    pdb_path: Path, cache: AnalysisCache, fingerprint: str
) -> CvdumpParser:
    cached: CvdumpParser | None = cache.load("cvdump-base", fingerprint)
    if cached is not None:
        return cached
    parser = (
        Cvdump(str(pdb_path))
        .lines()
        .globals()
        .publics()
        .section_contributions()
        .types()
        .modules()
        .run()
    )
    cache.store("cvdump-base", fingerprint, parser)
    return parser


def _load_module_cvdump(
    pdb_path: Path,
    module_id: int,
    cache: AnalysisCache,
    fingerprint: str,
) -> CvdumpParser:
    cache_name = f"cvdump-module-{module_id}"
    cached: CvdumpParser | None = cache.load(cache_name, fingerprint)
    if cached is not None:
        return cached
    parser = Cvdump(str(pdb_path)).symbols().module(module_id).run()
    cache.store(cache_name, fingerprint, parser)
    return parser


def _load_source_markers(
    target: RecCmpTarget,
    code_files: list[TextFile],
    cache: AnalysisCache,
    *,
    use_cache: bool,
) -> tuple[DecompCodebase, str]:
    marker_fingerprint = ""
    codebase: DecompCodebase | None = None
    if use_cache:
        marker_code_fingerprint = fingerprint_files(
            _MARKER_CACHE_INPUTS, context="marker-parser-v1"
        )
        marker_context = json.dumps(
            {
                "target": target.target_id,
                "aliases": target.marker_aliases,
                "parser": marker_code_fingerprint,
            },
            sort_keys=True,
        )
        marker_fingerprint = fingerprint_text_files(code_files, context=marker_context)
        codebase = cache.load("source-markers", marker_fingerprint)
    if codebase is None:
        codebase = DecompCodebase(
            code_files,
            target.target_id,
            aliases={target.target_id: target.marker_aliases},
        )
        cache.store("source-markers", marker_fingerprint, codebase)
    return codebase, marker_fingerprint


def _load_cvdump(
    target: RecCmpTarget,
    recomp_bin: Image,
    codebase: DecompCodebase,
    orig_addrs: tuple[int, ...],
    recomp_addrs: tuple[int, ...],
    cache: AnalysisCache,
    *,
    use_cache: bool,
) -> tuple[CvdumpParser, str, str]:
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    pdb_fingerprint = (
        fingerprint_files(
            (target.recompiled_pdb, *_CVDUMP_CACHE_INPUTS),
            context="cvdump-analysis-v1",
        )
        if use_cache
        else ""
    )
    if not orig_addrs and not recomp_addrs:
        return (
            _load_full_cvdump(target.recompiled_pdb, cache, pdb_fingerprint),
            pdb_fingerprint,
            "full",
        )

    cvdump = _load_base_cvdump(target.recompiled_pdb, cache, pdb_fingerprint)
    symbols_by_address = codebase.symbols_for_offsets(orig_addrs)
    symbol_hints = {
        SymbolModuleHint(
            source_file=symbol.filename,
            lookup_name=symbol.name if symbol.is_nameref() else None,
        )
        for symbols in symbols_by_address.values()
        for symbol in symbols
    }
    selection = select_modules(cvdump, recomp_bin, symbol_hints, recomp_addrs)
    if selection.requires_full_symbols:
        logger.debug(
            "Targeted cvdump module selection was ambiguous; using full symbols"
        )
        return (
            _load_full_cvdump(target.recompiled_pdb, cache, pdb_fingerprint),
            pdb_fingerprint,
            "full",
        )

    logger.debug(
        "Targeted cvdump modules: %s",
        ", ".join(str(value) for value in sorted(selection.module_ids)) or "none",
    )
    for module_id in sorted(selection.module_ids):
        merge_module_symbols(
            cvdump,
            _load_module_cvdump(
                target.recompiled_pdb, module_id, cache, pdb_fingerprint
            ),
        )
    symbol_scope = "modules:" + ",".join(
        str(value) for value in sorted(selection.module_ids)
    )
    return cvdump, pdb_fingerprint, symbol_scope


def load_target_analysis(
    target: RecCmpTarget,
    *,
    orig_addrs: Iterable[int] = (),
    recomp_addrs: Iterable[int] = (),
    use_cache: bool = True,
) -> LoadedTargetAnalysis:
    """Load fresh binaries plus cached deterministic analysis inputs."""
    orig_addrs = tuple(orig_addrs)
    recomp_addrs = tuple(recomp_addrs)
    orig_bin = detect_image(filepath=target.original_path)
    recomp_bin = detect_image(filepath=target.recompiled_path)

    code_files = list(
        TextFile.from_files(
            source_code_search(target.source_paths),
            allow_error=True,
            encoding=target.encoding or "utf-8",
        )
    )
    cache = AnalysisCache(
        target.recompiled_pdb.parent / ".reccmp-cache", enabled=use_cache
    )
    codebase, marker_fingerprint = _load_source_markers(
        target, code_files, cache, use_cache=use_cache
    )

    logger.info("Parsing %s ...", target.recompiled_pdb)
    cvdump, pdb_fingerprint, symbol_scope = _load_cvdump(
        target,
        recomp_bin,
        codebase,
        orig_addrs,
        recomp_addrs,
        cache,
        use_cache=use_cache,
    )
    pdb_file = CvdumpAnalysis(cvdump)

    data_sources = list(
        TextFile.from_files(
            target.data_sources,
            allow_error=True,
            encoding=target.encoding or "utf-8",
        )
    )
    prepared_fingerprint = ""
    if use_cache:
        data_fingerprint = fingerprint_text_files(
            data_sources, context="data-sources-v1"
        )
        prepared_context = json.dumps(
            {
                "target": target.target_id,
                "encoding": target.encoding,
                "aliases": target.marker_aliases,
                "markers": marker_fingerprint,
                "pdb": pdb_fingerprint,
                "data": data_fingerprint,
                "data_order": [str(source.path) for source in data_sources],
                "symbols": symbol_scope,
            },
            sort_keys=True,
        )
        prepared_fingerprint = fingerprint_files(
            (target.original_path, target.recompiled_path, *_COMPARE_CACHE_INPUTS),
            context=prepared_context,
        )

    return LoadedTargetAnalysis(
        orig_bin=orig_bin,
        recomp_bin=recomp_bin,
        pdb_file=pdb_file,
        code_files=code_files,
        data_sources=data_sources,
        project_aliases={target.target_id: target.marker_aliases},
        codebase=codebase,
        cache=cache,
        prepared_cache_name=(
            "prepared-full" if symbol_scope == "full" else "prepared-targeted"
        ),
        prepared_fingerprint=prepared_fingerprint,
    )
