import logging
import difflib
import struct
from typing import Iterable, Iterator
from typing_extensions import Self
from reccmp.project.detect import RecCmpTarget
from reccmp.isledecomp.dir import walk_source_dir
from reccmp.isledecomp.compare.diff import FunctionCompareResult, RawDiffOutput
from reccmp.isledecomp.compare.functions import FunctionComparator
from reccmp.isledecomp.formats import (
    Image,
    PEImage,
    TextFile,
    detect_image,
)
from reccmp.isledecomp.cvdump import Cvdump, CvdumpTypesParser, CvdumpAnalysis
from reccmp.isledecomp.types import EntityType, ImageId
from reccmp.isledecomp.compare.event import (
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
    match_ref,
    match_imports,
)
from .db import EntityDb, ReccmpEntity, ReccmpMatch
from .diff import DiffReport
from .lines import LinesDb
from .analyze import (
    create_imports,
    create_import_thunks,
    create_thunks,
    create_analysis_floats,
    create_analysis_strings,
    create_analysis_vtordisps,
    create_seh_entities,
    complete_partial_floats,
    complete_partial_strings,
    match_entry,
    match_exports,
)
from .ingest import (
    load_cvdump,
    load_cvdump_types,
    load_cvdump_lines,
    load_markers,
    load_data_sources,
)
from .mutate import (
    match_array_elements,
    name_thunks,
    unique_names_for_overloaded_functions,
)
from .verify import (
    check_vtables,
)


logger = logging.getLogger(__name__)


class Compare:
    # pylint: disable=too-many-instance-attributes
    _db: EntityDb
    _debug: bool
    _lines_db: LinesDb
    code_files: list[TextFile]
    cvdump_analysis: CvdumpAnalysis
    orig_bin: Image
    recomp_bin: Image
    report: ReccmpReportProtocol
    target_id: str
    types: CvdumpTypesParser
    function_comparator: FunctionComparator
    data_sources: list[TextFile]

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        orig_bin: Image,
        recomp_bin: Image,
        pdb_file: CvdumpAnalysis,
        target_id: str,
        code_files: list[TextFile] | None = None,
        data_sources: list[TextFile] | None = None,
    ):
        self.orig_bin = orig_bin
        self.recomp_bin = recomp_bin
        self.cvdump_analysis = pdb_file
        self.target_id = target_id

        if isinstance(code_files, list):
            self.code_files = code_files
        else:
            self.code_files = []

        if isinstance(data_sources, list):
            self.data_sources = data_sources
        else:
            self.data_sources = []

        # Controls whether we dump the asm output to a file
        self._debug = False

        self._lines_db = LinesDb()
        self._db = EntityDb()

        # For now, just redirect match alerts to the logger.
        self.report = create_logging_wrapper(logger)

        self.types = CvdumpTypesParser()

        self.function_comparator = FunctionComparator(
            self._db, self._lines_db, self.orig_bin, self.recomp_bin, self.report
        )

    def run(self):
        if not isinstance(self.orig_bin, PEImage) or not isinstance(
            self.recomp_bin, PEImage
        ):
            return

        load_cvdump_types(self.cvdump_analysis, self.types)
        load_cvdump(self.cvdump_analysis, self._db, self.recomp_bin)
        load_cvdump_lines(self.cvdump_analysis, self._lines_db, self.recomp_bin)

        match_entry(self._db, self.orig_bin, self.recomp_bin)

        load_markers(
            self.code_files,
            self._lines_db,
            self.orig_bin,
            self.target_id,
            self._db,
            self.report,
        )

        load_data_sources(self._db, self.data_sources)

        # Match using PDB and annotation data
        match_symbols(self._db, self.report, truncate=True)
        match_functions(self._db, self.report, truncate=True)
        match_vtables(self._db, self.report)
        match_static_variables(self._db, self.report)
        match_variables(self._db, self.report)
        match_lines(self._db, self._lines_db, self.report)

        match_array_elements(self._db, self.types)
        # Detect floats first to eliminate potential overlap with string data
        for img_id, binfile in (
            (ImageId.ORIG, self.orig_bin),
            (ImageId.RECOMP, self.recomp_bin),
        ):
            create_imports(self._db, img_id, binfile)
            create_import_thunks(self._db, img_id, binfile)
            create_analysis_floats(self._db, img_id, binfile)
            create_analysis_strings(self._db, img_id, binfile)
            create_seh_entities(self._db, img_id, binfile)
            create_thunks(self._db, img_id, binfile)
            create_analysis_vtordisps(self._db, img_id, binfile)
            complete_partial_floats(self._db, img_id, binfile)
            complete_partial_strings(self._db, img_id, binfile)

        match_imports(self._db)
        match_exports(self._db, self.orig_bin, self.recomp_bin)
        check_vtables(self._db, self.orig_bin)
        match_ref(self._db, self.report)
        unique_names_for_overloaded_functions(self._db)
        name_thunks(self._db)

        match_strings(self._db, self.report)

    @classmethod
    def from_target(cls, target: RecCmpTarget) -> Self:
        origfile = detect_image(filepath=target.original_path)
        recompfile = detect_image(filepath=target.recompiled_path)

        logger.info("Parsing %s ...", target.recompiled_pdb)
        cvdump = (
            Cvdump(str(target.recompiled_pdb))
            .lines()
            .globals()
            .publics()
            .symbols()
            .section_contributions()
            .types()
            .run()
        )
        pdb_file = CvdumpAnalysis(cvdump)

        code_paths = walk_source_dir(target.source_root)
        code_files = list(TextFile.from_files(code_paths, allow_error=True))

        data_sources = list(TextFile.from_files(target.data_sources, allow_error=True))

        compare = cls(
            origfile,
            recompfile,
            pdb_file,
            target_id=target.target_id,
            data_sources=data_sources,
            code_files=code_files,
        )
        compare.run()
        return compare

    @property
    def debug(self) -> bool:
        return self._debug

    @debug.setter
    def debug(self, debug: bool):
        self._debug = debug
        self.function_comparator.debug = debug

    def _compare_vtable(self, match: ReccmpMatch) -> FunctionCompareResult:
        vtable_size = match.size

        # The vtable size should always be a multiple of 4 because that
        # is the pointer size. If it is not (for whatever reason)
        # it would cause iter_unpack to blow up so let's just fix it.
        if vtable_size % 4 != 0:
            logger.warning(
                "Vtable for class %s has irregular size %d", match.name, vtable_size
            )
            vtable_size = 4 * (vtable_size // 4)

        orig_table = self.orig_bin.read(match.orig_addr, vtable_size)
        recomp_table = self.recomp_bin.read(match.recomp_addr, vtable_size)

        raw_addrs = zip(
            [t for (t,) in struct.iter_unpack("<L", orig_table)],
            [t for (t,) in struct.iter_unpack("<L", recomp_table)],
        )

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
            orig = self._db.get_by_orig(raw_orig)
            recomp = self._db.get_by_recomp(raw_recomp)

            if (
                orig is not None
                and recomp is not None
                and orig.recomp_addr == recomp.recomp_addr
            ):
                ratio += 1

            n_entries += 1
            index = f"vtable0x{i*4:02x}"
            orig_text.append((index, match_text(orig, raw_orig)))
            recomp_text.append((index, match_text(recomp)))

        ratio = ratio / float(n_entries) if n_entries > 0 else 0.0

        opcodes = difflib.SequenceMatcher(
            None,
            [x[1] for x in orig_text],
            [x[1] for x in recomp_text],
        ).get_opcodes()

        return FunctionCompareResult(
            diff=RawDiffOutput(
                # TODO: type conflict here between `str` and the literal strings.
                codes=list(opcodes),
                orig_inst=orig_text,
                recomp_inst=recomp_text,
            ),
            match_ratio=ratio,
        )

    def _compare_match(self, match: ReccmpMatch) -> DiffReport | None:
        """Router for comparison type"""

        if match.size is None or match.size == 0:
            return None

        if match.get("skip", False):
            return None

        assert match.entity_type is not None
        assert match.name is not None
        if match.get("stub", False):
            return DiffReport(
                match_type=EntityType(match.entity_type),
                orig_addr=match.orig_addr,
                recomp_addr=match.recomp_addr,
                name=match.name,
                is_stub=True,
            )

        # We only compare certain entity types in reccmp-asmcmp:
        if match.entity_type in (EntityType.FUNCTION, EntityType.VTORDISP):
            # Thunks are excluded from comparison. They always match 100% because
            # they are paired up using the destination of their JMP instruction.
            result = self.function_comparator.compare_function(match)
            output_type = EntityType.FUNCTION

        elif match.entity_type == EntityType.VTABLE:
            result = self._compare_vtable(match)
            output_type = EntityType.VTABLE

        else:
            return None

        best_name = match.best_name()
        assert best_name is not None

        return DiffReport(
            match_type=output_type,
            orig_addr=match.orig_addr,
            recomp_addr=match.recomp_addr,
            name=best_name,
            result=result,
            is_library=match.get("library", False),
        )

    ## Public API

    def is_pointer_match(self, orig_addr, recomp_addr) -> bool:
        """Check whether these pointers point at the same thing"""

        # Null pointers considered matching
        if orig_addr == 0 and recomp_addr == 0:
            return True

        match = self._db.get_by_orig(orig_addr)
        if match is None:
            return False

        return match.recomp_addr == recomp_addr

    def get_by_orig(self, addr: int) -> ReccmpEntity | None:
        return self._db.get_by_orig(addr)

    def get_by_recomp(self, addr: int) -> ReccmpEntity | None:
        return self._db.get_by_recomp(addr)

    def get_all(self) -> Iterator[ReccmpEntity]:
        return self._db.get_all()

    def get_functions(self) -> Iterator[ReccmpMatch]:
        return self._db.get_functions()

    def get_vtables(self) -> Iterator[ReccmpMatch]:
        return self._db.get_matches_by_type(EntityType.VTABLE)

    def get_variables(self) -> Iterator[ReccmpMatch]:
        return self._db.get_matches_by_type(EntityType.DATA)

    def compare_address(self, addr: int) -> DiffReport | None:
        match = self._db.get_one_match(addr)
        if match is None:
            return None

        return self._compare_match(match)

    def compare_all(self) -> Iterable[DiffReport]:
        for match in self._db.get_matches():
            diff = self._compare_match(match)
            if diff is not None:
                yield diff

    def compare_functions(self) -> Iterable[DiffReport]:
        for match in self.get_functions():
            diff = self._compare_match(match)
            if diff is not None:
                yield diff

    def compare_vtables(self) -> Iterable[DiffReport]:
        for match in self.get_vtables():
            diff = self._compare_match(match)
            if diff is not None:
                yield diff
