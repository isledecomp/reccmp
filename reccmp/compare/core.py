import logging
import difflib
import struct
from itertools import zip_longest
from typing import Callable, Iterable, Iterator
from typing_extensions import Self
from reccmp.project.detect import RecCmpTarget
from reccmp.compare.diff import EntityCompareResult, RawDiffOutput
from reccmp.compare.diagnosis import ComparisonAnalysis
from reccmp.parser import DecompCodebase
from reccmp.parser.marker import ProjectAliases, normalize_project_aliases
from reccmp.compare.equivalence import canonical_orig_addr, parse_equivalence_groups
from reccmp.compare.functions import FunctionComparator
from reccmp.formats import (
    Image,
    PEImage,
    TextFile,
)
from reccmp.cvdump import CvdumpTypesParser, CvdumpAnalysis
from reccmp.types import EntityType, ImageId
from reccmp.compare.event import (
    ReccmpReportProtocol,
    create_logging_wrapper,
)
from .match_msvc import (
    match_lines,
    match_symbols,
    match_functions,
    match_vtables,
    match_static_variables,
    match_variables,
    match_strings,
    classify_exact_string_aliases,
    match_ref,
    match_imports,
    match_seh,
)
from .db import EntityDb, ReccmpEntity, ReccmpMatch
from .lines import LinesDb
from .report import ReccmpComparedEntity, ReccmpStatusReport
from .target_analysis import PreparedAnalysis, load_target_analysis
from .thunk_resolve import effective_orig_vtable_size, resolve_vtable_slot
from .analyze import (
    create_imports,
    create_import_thunks,
    create_thunks,
    create_analysis_floats,
    create_analysis_strings,
    create_analysis_vtordisps,
    create_crt_functions,
    create_seh_entities,
    complete_partial_floats,
    complete_partial_strings,
    match_entry,
    match_exports,
    import_sections,
    normalize_original_zero_size_data,
    classify_exact_vtable_aliases,
)
from .ingest import (
    load_cvdump,
    load_cvdump_types,
    load_cvdump_lines,
    load_markers,
    load_data_sources,
)
from .mutate import (
    name_thunks,
    unique_names_for_overloaded_functions,
    match_crt_startup,
    set_max_size,
)
from .verify import (
    check_vtables,
)

logger = logging.getLogger(__name__)


class Compare:
    # pylint: disable=too-many-instance-attributes
    _db: EntityDb
    _lines_db: LinesDb
    code_files: list[TextFile]
    cvdump_analysis: CvdumpAnalysis
    orig_bin: Image
    recomp_bin: Image
    report: ReccmpReportProtocol
    target_id: str
    src_encoding: str
    bin_encoding: str
    types: CvdumpTypesParser
    function_comparator: FunctionComparator
    data_sources: list[TextFile]
    project_aliases: ProjectAliases
    codebase: DecompCodebase | None

    # pylint: disable=too-many-arguments
    # pylint: disable=too-many-positional-arguments
    def __init__(
        self,
        orig_bin: Image,
        recomp_bin: Image,
        pdb_file: CvdumpAnalysis,
        target_id: str,
        encoding: str | None = None,
        code_files: list[TextFile] | None = None,
        data_sources: list[TextFile] | None = None,
        project_aliases: ProjectAliases | None = None,
        codebase: DecompCodebase | None = None,
        equivalence_sources: list[TextFile] | None = None,
    ):
        self.orig_bin = orig_bin
        self.recomp_bin = recomp_bin
        self.cvdump_analysis = pdb_file
        self.target_id = target_id
        self.src_encoding = encoding or "utf-8"
        self.bin_encoding = encoding or "latin1"
        self.project_aliases = normalize_project_aliases(project_aliases or {})
        self.codebase = codebase

        if isinstance(code_files, list):
            self.code_files = code_files
        else:
            self.code_files = []

        if isinstance(data_sources, list):
            self.data_sources = data_sources
        else:
            self.data_sources = []

        self.equivalence_sources = (
            equivalence_sources if isinstance(equivalence_sources, list) else []
        )
        self.equivalence_groups = parse_equivalence_groups(self.equivalence_sources)

        self._lines_db = LinesDb()
        self._db = EntityDb()

        # For now, just redirect match alerts to the logger.
        self.report = create_logging_wrapper(logger)

        self.types = CvdumpTypesParser()

        self.function_comparator = FunctionComparator(
            self._db,
            self._lines_db,
            self.orig_bin,
            self.recomp_bin,
            self.report,
            self.types,
            equivalence_groups=self.equivalence_groups,
        )

    def _configure_function_nodes(self) -> None:
        if isinstance(self.recomp_bin, PEImage):
            for node in self.cvdump_analysis.nodes:
                if self.recomp_bin.is_valid_section(node.section):
                    node.addr = self.recomp_bin.get_abs_addr(node.section, node.offset)
        self.function_comparator.func_nodes = {
            node.addr: node
            for node in self.cvdump_analysis.nodes
            if node.addr is not None
            and (node.symbol_entry is not None or node.decorated_name is not None)
        }

    def _prepared_analysis(self) -> PreparedAnalysis:
        return PreparedAnalysis(self._db, self._lines_db, self.types)

    def _restore_prepared_analysis(self, analysis: PreparedAnalysis) -> None:
        self._db = analysis.db
        self._lines_db = analysis.lines_db
        self.types = analysis.types
        self.function_comparator = FunctionComparator(
            self._db,
            self._lines_db,
            self.orig_bin,
            self.recomp_bin,
            self.report,
            self.types,
            equivalence_groups=self.equivalence_groups,
        )
        self._configure_function_nodes()

    def run(self):
        if not isinstance(self.orig_bin, PEImage) or not isinstance(
            self.recomp_bin, PEImage
        ):
            return

        # Each task creates new entities or overwrites existing data.
        # The tasks are ordered roughly according to the principle
        # of highest-to-lowest confidence of data validity.
        load_cvdump_types(self.cvdump_analysis, self.types)
        load_cvdump(self.cvdump_analysis, self._db, self.recomp_bin)
        load_cvdump_lines(self.cvdump_analysis, self._lines_db, self.recomp_bin)

        # Function nodes (with their PDB type keys and decorated names) by
        # recomp address: lets the function comparator derive return kinds
        # and callee calling conventions for the effective-match verifier.
        self._configure_function_nodes()

        match_entry(self._db, self.orig_bin, self.recomp_bin)

        load_markers(
            self.code_files,
            self._lines_db,
            self.orig_bin,
            self.target_id,
            self._db,
            self.bin_encoding,
            self.project_aliases,
            self.report,
            self.codebase,
        )

        load_data_sources(self._db, self.data_sources)
        normalize_original_zero_size_data(self._db, self.orig_bin)

        # Match using PDB and annotation data
        truncate = self.cvdump_analysis.truncate_symbols
        match_symbols(self._db, self.report, truncate=truncate)
        match_functions(self._db, self.report, truncate=truncate)
        match_vtables(self._db, self.report)
        classify_exact_vtable_aliases(self._db, self.orig_bin, self.recomp_bin)
        match_static_variables(self._db, self.report)
        match_variables(self._db, self.report)
        match_lines(self._db, self._lines_db, self.report)

        # Detect floats first to eliminate potential overlap with string data
        for img_id, binfile in (
            (ImageId.ORIG, self.orig_bin),
            (ImageId.RECOMP, self.recomp_bin),
        ):
            create_imports(self._db, img_id, binfile)
            create_import_thunks(self._db, img_id, binfile)
            create_seh_entities(self._db, img_id, binfile)
            create_thunks(self._db, img_id, binfile)
            create_analysis_vtordisps(self._db, img_id, binfile)
            create_crt_functions(self._db, img_id, binfile)
            import_sections(self._db, img_id, binfile)

        match_imports(self._db)
        match_exports(self._db, self.orig_bin, self.recomp_bin)

        for img_id in (ImageId.ORIG, ImageId.RECOMP):
            set_max_size(self._db, img_id)

        match_crt_startup(self._db, self.orig_bin, self.recomp_bin)
        match_seh(self._db)

        match_ref(self._db, self.report)
        self.function_comparator.discover_unique_called_functions()
        self.function_comparator.discover_unpaired_function_bodies()
        unique_names_for_overloaded_functions(self._db)
        name_thunks(self._db)

        # Search for const data values and read bytes from the binaries.
        # This happens last because establishing all other entities first
        # will reduce false positives. For each address presumed to be a
        # float or string, skip if there is an existing entity at the address.
        for img_id, binfile in (
            (ImageId.ORIG, self.orig_bin),
            (ImageId.RECOMP, self.recomp_bin),
        ):
            # Some float consts may appear to be strings.
            # Detect floats first because we can identify them with more confidence
            # and this eliminates them from consideration as strings.
            create_analysis_floats(self._db, img_id, binfile)
            create_analysis_strings(self._db, img_id, binfile, self.bin_encoding)
            complete_partial_floats(self._db, img_id, binfile)
            complete_partial_strings(self._db, img_id, binfile, self.bin_encoding)

        match_strings(self._db, self.report)
        classify_exact_string_aliases(self._db)

    @classmethod
    def from_target(
        cls,
        target: RecCmpTarget,
        *,
        orig_addrs: Iterable[int] = (),
        recomp_addrs: Iterable[int] = (),
        use_cache: bool = True,
    ) -> Self:
        loaded = load_target_analysis(
            target,
            orig_addrs=orig_addrs,
            recomp_addrs=recomp_addrs,
            use_cache=use_cache,
        )
        compare = cls(
            loaded.orig_bin,
            loaded.recomp_bin,
            loaded.pdb_file,
            target_id=target.target_id,
            encoding=target.encoding,
            data_sources=loaded.data_sources,
            code_files=loaded.code_files,
            project_aliases=loaded.project_aliases,
            codebase=loaded.codebase,
            equivalence_sources=loaded.equivalence_sources,
        )
        prepared = loaded.load_prepared()
        if prepared is not None:
            compare._restore_prepared_analysis(prepared)
        else:
            compare.run()
            loaded.store_prepared(compare._prepared_analysis())
        return compare

    def report_vtable_size_warnings(self, name_filter: str | None = None) -> None:
        """Log oversized-vtable evidence, optionally limited by name."""
        check_vtables(self._db, self.orig_bin, name_filter)

    def _orig_addrs_equivalent(
        self, orig_addr: int | None, recomp_orig_addr: int | None
    ) -> bool:
        """True when both original addresses belong to the same proven
        equivalence group (fold islands / duplicate COMDATs)."""
        if not self.equivalence_groups:
            return False
        if orig_addr is None or recomp_orig_addr is None:
            return False
        return canonical_orig_addr(
            self.equivalence_groups, orig_addr
        ) == canonical_orig_addr(self.equivalence_groups, recomp_orig_addr)

    def _slot_alias_equivalent(
        self, raw_orig: int, recomp: "ReccmpEntity | None"
    ) -> bool:
        """Recomputed compiler-alias acceptance for one vtable slot.

        MSVC folds identical COMDAT bodies, so one original address may
        serve slots whose rebuilt targets are distinct functions, and only
        one of them (or none) can carry the annotation for the shared
        original body. The slot is still correct when the original body at
        the slot's target and the rebuilt body the recomp table installs
        are provably the same compiled code; that equivalence is recomputed
        from the bodies by {@link FunctionComparator.raw_pair_alias_equivalent}
        and holds only when every relocated operand resolves to a named,
        paired entity on both sides. Non-equivalent targets still fail.
        """
        if recomp is None or recomp.recomp_addr is None:
            return False
        if recomp.get("type") not in (EntityType.FUNCTION, None):
            return False
        size = recomp.size(ImageId.RECOMP)
        if size is None or size <= 0:
            return False
        return self.function_comparator.raw_pair_alias_equivalent(
            raw_orig, recomp.recomp_addr, size
        )

    def _compare_vtable(
        self, match: ReccmpMatch, *, include_diff: bool = True
    ) -> EntityCompareResult:
        recomp_size = match.any_size(ImageId.RECOMP)

        # The vtable size should always be a multiple of 4 because that
        # is the pointer size. If it is not (for whatever reason)
        # it would cause iter_unpack to blow up so let's just fix it.
        if recomp_size % 4 != 0:
            logger.warning(
                "Vtable for class %s has irregular size %d", match.name, recomp_size
            )
            recomp_size = 4 * (recomp_size // 4)

        # The PDB doesn't record a size for the vtable itself, so the recomp
        # size is an estimate: it's either the gap between this symbol and the
        # next, or the size listed in cvdump's SECTION CONTRIBUTIONS output.
        # Either estimate can include alignment padding after the table, and
        # reading the orig table with the padded size would run past the
        # actual end of the table. Just use the orig size if known.
        orig_size = match.size(ImageId.ORIG)
        if orig_size is None:
            orig_size = recomp_size
        elif orig_size % 4 != 0:
            logger.warning(
                "Vtable for class %s has irregular orig size %d", match.name, orig_size
            )
            orig_size = 4 * (orig_size // 4)

        orig_max = match.max_size(ImageId.ORIG)
        if orig_max is not None:
            orig_size = min(orig_size, orig_max)
        orig_size = effective_orig_vtable_size(self.orig_bin, match.orig_addr, orig_size)
        orig_table = self.orig_bin.read(match.orig_addr, orig_size)
        recomp_table = self.recomp_bin.read(match.recomp_addr, recomp_size)

        orig_addrs = [t for (t,) in struct.iter_unpack("<L", orig_table)]
        recomp_addrs = [t for (t,) in struct.iter_unpack("<L", recomp_table)]

        # Trailing null entries on the recomp side are alignment padding, not
        # virtual functions missing from orig, so drop them. Non-null entries
        # past the end of the orig table are kept: these are virtual functions
        # that only exist in recomp, and zip_longest will show them with
        # "(no match)" on the orig side.
        while len(recomp_addrs) > len(orig_addrs) and recomp_addrs[-1] == 0:
            recomp_addrs.pop()

        raw_addrs = zip_longest(orig_addrs, recomp_addrs)

        def match_text(m: ReccmpEntity | None, raw_addr: int | None = None) -> str:
            """Format the function reference at this vtable index as text.
            If we have not identified this function, we have the option to
            display the raw address. This is only worth doing for the original addr
            because we should always be able to identify the recomp function.
            If the original function is missing then this probably means that the class
            should override the given function from the superclass, but we have not
            implemented this yet.
            """

            if m is not None:
                orig = hex(m.orig_addr) if m.orig_addr is not None else "no orig"
                recomp = (
                    hex(m.recomp_addr) if m.recomp_addr is not None else "no recomp"
                )
                return f"({orig} / {recomp})  :  {m.best_name()}"

            if raw_addr is not None:
                return f"0x{raw_addr:x} from orig not annotated."

            return "(no match)"

        orig_text = []
        recomp_text = []
        ratio = 0.0
        n_entries = 0

        # Now compare each pointer from the two vtables.
        for i, (raw_orig, raw_recomp) in enumerate(raw_addrs):
            index = f"vtable0x{i*4:02x}"
            n_entries += 1

            # Orig binaries may contain literal NULL vtable slots (reserved gap).
            # MSVC cannot emit mid-table NULL entries, so accept any recomp slot.
            if raw_orig == 0:
                ratio += 1
                orig_text.append((index, "0x0 (null slot)"))
                recomp_text.append(
                    (
                        index,
                        match_text(
                            resolve_vtable_slot(
                                self._db,
                                ImageId.RECOMP,
                                self.recomp_bin,
                                raw_recomp,
                            )
                        ),
                    )
                )
                continue

            orig = resolve_vtable_slot(self._db, ImageId.ORIG, self.orig_bin, raw_orig)
            recomp = resolve_vtable_slot(
                self._db, ImageId.RECOMP, self.recomp_bin, raw_recomp
            )

            slot_matches = (
                orig is not None
                and recomp is not None
                and (
                    orig.recomp_addr == recomp.recomp_addr
                    or self._orig_addrs_equivalent(orig.orig_addr, recomp.orig_addr)
                )
            )
            if not slot_matches:
                slot_matches = self._slot_alias_equivalent(raw_orig, recomp)
            if slot_matches:
                ratio += 1

            orig_text.append((index, match_text(orig, raw_orig)))
            recomp_text.append((index, match_text(recomp)))

        ratio = ratio / float(n_entries) if n_entries > 0 else 0.0

        opcodes = difflib.SequenceMatcher(
            None,
            [x[1] for x in orig_text],
            [x[1] for x in recomp_text],
        ).get_opcodes()

        return EntityCompareResult(
            diff=(
                RawDiffOutput(
                    codes=opcodes,
                    orig_inst=orig_text,
                    recomp_inst=recomp_text,
                )
                if include_diff
                else RawDiffOutput()
            ),
            match_ratio=ratio,
            analysis=(
                ComparisonAnalysis.exact()
                if ratio == 1.0
                else ComparisonAnalysis.inconclusive("analysis_limit")
            ),
        )

    def _compare_non_match(self, ent: ReccmpEntity) -> ReccmpComparedEntity | None:
        assert ent.orig_addr is not None

        if ent.get("skip", False):
            return None

        assert ent.entity_type is not None

        if ent.entity_type in (EntityType.FUNCTION, EntityType.VTORDISP):
            output_type = EntityType.FUNCTION

        elif ent.entity_type == EntityType.VTABLE:
            output_type = EntityType.VTABLE

        else:
            return None

        name = ent.best_name()
        if name is None:
            name = f"Unknown {output_type.name}"

        return ReccmpComparedEntity(
            orig_addr=ent.orig_addr,
            name=name,
            accuracy=0.0,
            type=output_type,
            recomp_addr=None,
            is_stub=True,
            is_library=ent.get("library", False),
        )

    def _compare_match(
        self,
        match: ReccmpMatch,
        *,
        include_diff: bool = True,
        include_exact_diff: bool = True,
    ) -> ReccmpComparedEntity | None:
        """Router for comparison type"""

        if match.size is None or match.any_size() == 0:
            return None

        if match.get("skip", False):
            return None

        assert match.entity_type is not None
        assert match.name is not None

        # We only compare certain entity types in reccmp-asmcmp:
        if match.entity_type in (EntityType.FUNCTION, EntityType.VTORDISP):
            # Thunks are excluded from comparison. They always match 100% because
            # they are paired up using the destination of their JMP instruction.
            result = self.function_comparator.compare_function(
                match,
                include_diff=include_diff,
                include_exact_diff=include_exact_diff,
            )
            output_type = EntityType.FUNCTION

        elif match.entity_type == EntityType.VTABLE:
            result = self._compare_vtable(match, include_diff=include_diff)
            output_type = EntityType.VTABLE

        else:
            return None

        best_name = match.best_name()
        assert best_name is not None

        return ReccmpComparedEntity(
            orig_addr=match.orig_addr,
            name=best_name,
            accuracy=result.match_ratio,
            type=output_type,
            recomp_addr=match.recomp_addr,
            analysis=result.analysis,
            is_stub=match.get("stub", False),
            is_library=match.get("library", False),
            rdiff=result.diff,
        )

    ## Public API

    def get_all(self) -> Iterator[ReccmpEntity]:
        return self._db.get_all()

    def get_functions(self) -> Iterator[ReccmpMatch]:
        return self._db.get_functions()

    def get_unmatched(self, image_id: ImageId) -> Iterator[ReccmpEntity]:
        """Raw unmatched inventory, including proven duplicate bodies."""
        return self._db.unmatched(image_id)

    def get_unexplained(self, image_id: ImageId) -> Iterator[ReccmpEntity]:
        """Unmatched inventory excluding proven duplicate bodies."""
        return self._db.unexplained(image_id)

    def get_aliases(
        self, image_id: ImageId
    ) -> Iterator[tuple[ReccmpEntity, ReccmpMatch]]:
        """Proven side-local duplicates and their canonical pairs."""
        return self._db.get_aliases(image_id)

    def get_vtables(self) -> Iterator[ReccmpMatch]:
        return self._db.get_matches_by_type(EntityType.VTABLE)

    def get_variables(self) -> Iterator[ReccmpMatch]:
        return self._db.get_matches_by_type(EntityType.DATA)

    def compare_address(
        self,
        addr: int,
        *,
        include_diff: bool = True,
        include_exact_diff: bool = True,
    ) -> ReccmpComparedEntity | None:
        match = self._db.get_one_match(addr)
        if match is None:
            return None

        return self._compare_match(
            match,
            include_diff=include_diff,
            include_exact_diff=include_exact_diff,
        )

    def compare_addresses(
        self,
        orig_addrs: Iterable[int] = (),
        recomp_addrs: Iterable[int] = (),
        *,
        include_diff: bool = True,
        include_exact_diff: bool = True,
    ) -> Iterable[ReccmpComparedEntity]:
        """Compare a selected set of matches from either address space.

        A match requested through both address spaces is emitted once, ordered
        by original address. Unknown and non-comparable addresses are omitted.
        """
        selected: dict[int, ReccmpMatch] = {}
        for addr in orig_addrs:
            match = self._db.get_one_match(addr)
            if match is not None:
                selected[match.orig_addr] = match
        for addr in recomp_addrs:
            entity = self._db.get(ImageId.RECOMP, addr)
            if isinstance(entity, ReccmpMatch):
                selected[entity.orig_addr] = entity

        for orig_addr in sorted(selected):
            diff = self._compare_match(
                selected[orig_addr],
                include_diff=include_diff,
                include_exact_diff=include_exact_diff,
            )
            if diff is not None:
                yield diff

    def compare_all(
        self,
        filter_fn: Callable[[ReccmpEntity], bool] | None = None,
        *,
        include_diff: bool = True,
        include_exact_diff: bool = True,
    ) -> Iterator[ReccmpComparedEntity]:
        for ent in self._db.all(ImageId.ORIG):
            if ent.entity_type not in (
                EntityType.FUNCTION,
                EntityType.VTORDISP,
                EntityType.VTABLE,
            ):
                continue

            if filter_fn and not filter_fn(ent):
                continue

            if ent.recomp_addr is not None:
                assert isinstance(ent, ReccmpMatch)
                diff = self._compare_match(
                    ent,
                    include_diff=include_diff,
                    include_exact_diff=include_exact_diff,
                )
            else:
                diff = self._compare_non_match(ent)

            if diff is not None:
                yield diff

    def compare_functions(
        self, *, include_diff: bool = True, include_exact_diff: bool = True
    ) -> Iterable[ReccmpComparedEntity]:
        for match in self.get_functions():
            diff = self._compare_match(
                match,
                include_diff=include_diff,
                include_exact_diff=include_exact_diff,
            )
            if diff is not None:
                yield diff

    def compare_vtables(
        self, *, include_diff: bool = True
    ) -> Iterable[ReccmpComparedEntity]:
        for match in self.get_vtables():
            diff = self._compare_match(match, include_diff=include_diff)
            if diff is not None:
                yield diff

    def to_report(
        self,
        filename: str,
        filter_fn: Callable[[ReccmpEntity], bool] | None = None,
        *,
        include_diff: bool = True,
        include_exact_diff: bool = True,
    ) -> ReccmpStatusReport:
        """Creates a ReccmpStatusReport using the current reccmp state."""
        report = ReccmpStatusReport(filename=filename)
        for match in self.compare_all(
            filter_fn,
            include_diff=include_diff,
            include_exact_diff=include_exact_diff,
        ):
            report.add_match(match)

        return report
