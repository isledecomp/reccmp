import logging
import difflib
from pathlib import Path
import struct
from typing import Iterable, Iterator
from reccmp.project.detect import RecCmpTarget
from reccmp.isledecomp.difflib import get_grouped_opcodes
from reccmp.isledecomp.compare.functions import FunctionComparator
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualReadError,
    InvalidStringError,
)
from reccmp.isledecomp.formats.detect import detect_image
from reccmp.isledecomp.formats.pe import PEImage
from reccmp.isledecomp.cvdump.demangler import (
    demangle_string_const,
)
from reccmp.isledecomp.cvdump import Cvdump, CvdumpTypesParser, CvdumpAnalysis
from reccmp.isledecomp.parser import DecompCodebase
from reccmp.isledecomp.dir import walk_source_dir
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.compare.event import (
    ReccmpEvent,
    ReccmpReportProtocol,
    reccmp_report_nop,
    create_logging_wrapper,
)
from reccmp.isledecomp.analysis import (
    find_float_consts,
    find_import_thunks,
    find_vtordisp,
    is_likely_latin1,
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
)
from .db import EntityDb, ReccmpEntity, ReccmpMatch, entity_name_from_string
from .diff import DiffReport, combined_diff
from .lines import LinesDb
from .mutate import (
    match_array_elements,
    name_thunks,
    unique_names_for_overloaded_functions,
)


# pylint: disable=too-many-lines


logger = logging.getLogger(__name__)


class Compare:
    # pylint: disable=too-many-instance-attributes
    _db: EntityDb
    _debug: bool
    _lines_db: LinesDb
    code_dir: Path
    cvdump_analysis: CvdumpAnalysis
    orig_bin: PEImage
    recomp_bin: PEImage
    report: ReccmpReportProtocol
    target_id: str
    types: CvdumpTypesParser
    function_comparator: FunctionComparator

    def __init__(
        self,
        orig_bin: PEImage,
        recomp_bin: PEImage,
        pdb_file: CvdumpAnalysis,
        code_dir: Path | str,
        target_id: str,
    ):
        self.orig_bin = orig_bin
        self.recomp_bin = recomp_bin
        self.cvdump_analysis = pdb_file
        self.code_dir = Path(code_dir)
        self.target_id = target_id

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
        self._match_entry(self._db, self.orig_bin, self.recomp_bin)

        self._load_cvdump_types(self.cvdump_analysis, self.types)
        self._load_cvdump(self.cvdump_analysis, self._db, self.recomp_bin)
        self._load_cvdump_lines(self.cvdump_analysis, self._lines_db, self.recomp_bin)

        self._load_markers(
            self.code_dir,
            self._lines_db,
            self.orig_bin,
            self.target_id,
            self._db,
            self.report,
        )

        # Match using PDB and annotation data
        match_symbols(self._db, self.report, truncate=True)
        match_functions(self._db, self.report, truncate=True)
        match_vtables(self._db, self.report)
        match_static_variables(self._db, self.report)
        match_variables(self._db, self.report)
        match_lines(self._db, self._lines_db, self.report)

        match_array_elements(self._db, self.types)
        # Detect floats first to eliminate potential overlap with string data
        self._find_float_const(self._db, self.orig_bin, self.recomp_bin)
        self._find_strings(self._db, self.orig_bin, self.recomp_bin)
        self._match_imports(self._db, self.orig_bin, self.recomp_bin)
        self._match_exports(self._db, self.orig_bin, self.recomp_bin)
        self._create_thunks(self._db, self.orig_bin, self.recomp_bin)
        self._check_vtables(self._db, self.orig_bin)
        match_ref(self._db, self.report)
        unique_names_for_overloaded_functions(self._db)
        name_thunks(self._db)
        self._match_vtordisp(self._db, self.orig_bin, self.recomp_bin)

        match_strings(self._db, self.report)

    @classmethod
    def from_target(cls, target: RecCmpTarget):
        origfile = detect_image(filepath=target.original_path)
        if not isinstance(origfile, PEImage):
            raise ValueError(f"{target.original_path} is not a PE executable")

        recompfile = detect_image(filepath=target.recompiled_path)
        if not isinstance(recompfile, PEImage):
            raise ValueError(f"{target.recompiled_path} is not a PE executable")

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

        compare = cls(
            origfile,
            recompfile,
            pdb_file,
            target.source_root,
            target_id=target.target_id,
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

    def _load_cvdump_types(
        self, cvdump_analysis: CvdumpAnalysis, types: CvdumpTypesParser
    ):
        # TODO: Populate the universal type database here when this exists. (#106)
        # For now, just copy the keys into another CvdumpTypesParser so we can use its API.
        types.keys.update(cvdump_analysis.types.keys)

    def _load_cvdump(
        self, cvdump_analysis: CvdumpAnalysis, db: EntityDb, recomp_bin: PEImage
    ):
        # Build the list of entries to insert to the DB.
        # In the rare case we have duplicate symbols for an address, ignore them.
        seen_addrs = set()

        with db.batch() as batch:
            for sym in cvdump_analysis.nodes:
                # Skip nodes where we have almost no information.
                # These probably came from SECTION CONTRIBUTIONS.
                if sym.name() is None and sym.node_type is None:
                    continue

                # The PDB might contain sections that do not line up with the
                # actual binary. The symbol "__except_list" is one example.
                # In these cases, just skip this symbol and move on because
                # we can't do much with it.
                if not recomp_bin.is_valid_section(sym.section):
                    continue

                addr = recomp_bin.get_abs_addr(sym.section, sym.offset)
                sym.addr = addr

                if addr in seen_addrs:
                    continue

                seen_addrs.add(addr)

                # If this symbol is the final one in its section, we were not able to
                # estimate its size because we didn't have the total size of that section.
                # We can get this estimate now and assume that the final symbol occupies
                # the remainder of the section.
                if sym.estimated_size is None:
                    sym.estimated_size = (
                        recomp_bin.get_section_extent_by_index(sym.section) - sym.offset
                    )

                if sym.node_type == EntityType.STRING:
                    assert sym.decorated_name is not None
                    string_info = demangle_string_const(sym.decorated_name)
                    if string_info is None:
                        logger.debug(
                            "Could not demangle string symbol: %s", sym.decorated_name
                        )
                        continue

                    try:
                        # Use the section contribution size if we have it. It is more accurate
                        # than the number embedded in the string symbol:
                        #
                        #     e.g. ??_C@_0BA@EFDM@MxObjectFactory?$AA@
                        #     reported length: 16 (includes null terminator)
                        #     c.f. ??_C@_03DPKJ@enz?$AA@
                        #     reported length: 3 (does NOT include terminator)
                        #
                        # Using a known length enables us to read strings that include null bytes.
                        # string_size is the total memory footprint, including null-terminator.
                        if string_info.is_utf16:
                            if sym.section_contribution is not None:
                                string_size = sym.section_contribution
                                # Remove 2-byte null-terminator before decoding
                                raw = recomp_bin.read(addr, string_size)[:-2]
                            else:
                                raw = recomp_bin.read_widechar(addr)
                                string_size = len(raw) + 2

                            decoded_string = raw.decode("utf-16-le")
                        else:
                            if sym.section_contribution is not None:
                                string_size = sym.section_contribution
                                # Remove 1-byte null-terminator before decoding
                                raw = recomp_bin.read(addr, string_size)[:-1]
                            else:
                                raw = recomp_bin.read_string(addr)
                                string_size = len(raw) + 1

                            decoded_string = raw.decode("latin1")

                    except (InvalidVirtualReadError, InvalidStringError):
                        logger.warning(
                            "Could not read string from recomp 0x%x, wide=%s",
                            addr,
                            string_info.is_utf16,
                        )

                    except UnicodeDecodeError:
                        logger.warning(
                            "Could not decode string: %s, wide=%s",
                            raw,
                            string_info.is_utf16,
                        )
                        continue

                    # Special handling for string entities.
                    # Make sure the entity size includes the string null-terminator.
                    batch.set_recomp(
                        addr,
                        type=sym.node_type,
                        name=entity_name_from_string(
                            decoded_string, wide=string_info.is_utf16
                        ),
                        symbol=sym.decorated_name,
                        size=string_size,
                        verified=True,
                    )
                else:
                    # Non-string entities.
                    batch.set_recomp(
                        addr,
                        type=sym.node_type,
                        name=sym.name(),
                        symbol=sym.decorated_name,
                        size=sym.size(),
                    )

                    # Set the cvdump type key so it can be referenced later.
                    if sym.node_type == EntityType.DATA and sym.data_type is not None:
                        batch.set_recomp(addr, data_type=sym.data_type.key)

    def _load_cvdump_lines(
        self, cvdump_analysis: CvdumpAnalysis, lines_db: LinesDb, recomp_bin: PEImage
    ):
        for filename, values in cvdump_analysis.lines.items():
            lines = [
                (v.line_number, recomp_bin.get_abs_addr(v.section, v.offset))
                for v in values
            ]
            lines_db.add_lines(filename, lines)

        # The seen_addrs set has more than functions, but the intersection of
        # these addrs and the code lines should be just the functions.
        seen_addrs = set(
            # TODO: Ideally this conversion and filtering would happen inside CvdumpAnalysis.
            recomp_bin.get_abs_addr(node.section, node.offset)
            for node in cvdump_analysis.nodes
            if recomp_bin.is_valid_section(node.section)
        )

        lines_db.mark_function_starts(tuple(seen_addrs))

    def _match_entry(self, db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
        # The _entry symbol is referenced in the PE header so we get this match for free.
        with db.batch() as batch:
            batch.set_recomp(recomp_bin.entry, type=EntityType.FUNCTION)
            batch.match(orig_bin.entry, recomp_bin.entry)

    # pylint: disable=too-many-arguments
    def _load_markers(
        self,
        code_dir: Path,
        lines_db: LinesDb,
        orig_bin: PEImage,
        target_id: str,
        db: EntityDb,
        report: ReccmpReportProtocol = reccmp_report_nop,
    ):
        codefiles = [Path(p) for p in walk_source_dir(code_dir)]
        lines_db.add_local_paths(codefiles)
        codebase = DecompCodebase(codefiles, target_id)

        # If the address of any annotation would cause an exception,
        # remove it and report an error.
        bad_annotations = codebase.prune_invalid_addrs(orig_bin.is_valid_vaddr)

        for sym in bad_annotations:
            report(
                ReccmpEvent.INVALID_USER_DATA,
                sym.offset,
                msg=f"Invalid address 0x{sym.offset:x} on {sym.type.name} annotation in file: {sym.filename}",
            )

        # Make sure each address is used only once
        duplicate_annotations = codebase.prune_reused_addrs()

        for sym in duplicate_annotations:
            report(
                ReccmpEvent.INVALID_USER_DATA,
                sym.offset,
                msg=f"Dropped duplicate address 0x{sym.offset:x} on {sym.type.name} annotation in file: {sym.filename}",
            )

        # Match lineref functions first because this is a guaranteed match.
        # If we have two functions that share the same name, and one is
        # a lineref, we can match the nameref correctly because the lineref
        # was already removed from consideration.
        with db.batch() as batch:
            for fun in codebase.iter_line_functions():
                batch.set_orig(
                    fun.offset, type=EntityType.FUNCTION, stub=fun.should_skip()
                )

                assert fun.filename is not None
                recomp_addr = lines_db.find_function(
                    fun.filename, fun.line_number, fun.end_line
                )

                if recomp_addr is not None:
                    batch.match(fun.offset, recomp_addr)

            for fun in codebase.iter_name_functions():
                batch.set_orig(
                    fun.offset,
                    type=EntityType.FUNCTION,
                    stub=fun.should_skip(),
                    library=fun.is_library(),
                )

                if fun.name.startswith("?") or fun.name_is_symbol:
                    batch.set_orig(fun.offset, symbol=fun.name)
                else:
                    batch.set_orig(fun.offset, name=fun.name)

            for var in codebase.iter_variables():
                batch.set_orig(var.offset, name=var.name, type=EntityType.DATA)
                if var.is_static and var.parent_function is not None:
                    batch.set_orig(
                        var.offset, static_var=True, parent_function=var.parent_function
                    )

            for tbl in codebase.iter_vtables():
                batch.set_orig(
                    tbl.offset,
                    name=tbl.name,
                    base_class=tbl.base_class,
                    type=EntityType.VTABLE,
                )

            for string in codebase.iter_strings():
                # Not that we don't trust you, but we're checking the string
                # annotation to make sure it is accurate.
                try:
                    if string.is_widechar:
                        string_size = 2 * len(string.name) + 2
                        raw = orig_bin.read(string.offset, string_size)
                        orig = raw.decode("utf-16-le")
                    else:
                        string_size = len(string.name) + 1
                        raw = orig_bin.read(string.offset, string_size)
                        orig = raw.decode("latin1")

                    string_correct = orig[-1] == "\0" and string.name == orig[:-1]

                except InvalidStringError:
                    logger.warning(
                        "Could not read string from orig 0x%x, wide=%s",
                        string.offset,
                        string.is_widechar,
                    )
                    string_correct = False

                except UnicodeDecodeError:
                    logger.warning(
                        "Could not decode string: %s, wide=%s",
                        raw,
                        string.is_widechar,
                    )
                    string_correct = False

                if not string_correct:
                    report(
                        ReccmpEvent.INVALID_USER_DATA,
                        string.offset,
                        msg=f"Data at 0x{string.offset:x} does not match string {repr(string.name)}",
                    )
                    continue

                batch.set_orig(
                    string.offset,
                    name=entity_name_from_string(string.name, wide=string.is_widechar),
                    type=EntityType.STRING,
                    size=string_size,
                    verified=True,
                )

            for line in codebase.iter_line_symbols():
                batch.set_orig(
                    line.offset,
                    name=line.name,
                    filename=line.filename,
                    line=line.line_number,
                    type=EntityType.LINE,
                )

    def _find_strings(self, db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
        """Search both binaries for Latin1 strings.
        We use the insert_() method so that thse strings will not overwrite
        an existing entity. It's possible that some variables or pointers
        will be mistakenly identified as short strings."""
        with db.batch() as batch:
            for addr, string in orig_bin.iter_string("latin1"):
                # If the address is the site of a relocation, this is a pointer, not a string.
                if addr in orig_bin.relocations:
                    continue

                if is_likely_latin1(string) and not db.orig_used(addr):
                    batch.set_orig(
                        addr,
                        type=EntityType.STRING,
                        name=entity_name_from_string(string),
                        size=len(string) + 1,  # including null-terminator
                    )

            for addr, string in recomp_bin.iter_string("latin1"):
                if addr in recomp_bin.relocations:
                    continue

                if is_likely_latin1(string) and not db.recomp_used(addr):
                    batch.set_recomp(
                        addr,
                        type=EntityType.STRING,
                        name=entity_name_from_string(string),
                        size=len(string) + 1,  # including null-terminator
                    )

    def _find_float_const(self, db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
        """Add floating point constants in each binary to the database.
        We are not matching anything right now because these values are not
        deduped like strings."""
        with db.batch() as batch:
            for addr, size, float_value in find_float_consts(orig_bin):
                if not db.orig_used(addr):
                    batch.set_orig(
                        addr, type=EntityType.FLOAT, name=str(float_value), size=size
                    )

            for addr, size, float_value in find_float_consts(recomp_bin):
                if not db.recomp_used(addr):
                    batch.set_recomp(
                        addr, type=EntityType.FLOAT, name=str(float_value), size=size
                    )

    def _match_imports(self, db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
        """We can match imported functions based on the DLL name and
        function symbol name."""
        orig_byaddr = {
            addr: (dll.upper(), name) for (dll, name, addr) in orig_bin.imports
        }
        recomp_byname = {
            (dll.upper(), name): addr for (dll, name, addr) in recomp_bin.imports
        }

        with db.batch() as batch:
            for dll, name, addr in orig_bin.imports:
                import_name = f"{dll}::{name}"
                batch.set_orig(
                    addr,
                    name=import_name,
                    size=4,
                    type=EntityType.IMPORT,
                )

            for dll, name, addr in recomp_bin.imports:
                import_name = f"{dll}::{name}"
                batch.set_recomp(
                    addr,
                    name=import_name,
                    size=4,
                    type=EntityType.IMPORT,
                )

            # Combine these two dictionaries. We don't care about imports from recomp
            # not found in orig because:
            # 1. They shouldn't be there
            # 2. They are already identified via cvdump
            for orig_addr, pair in orig_byaddr.items():
                recomp_addr = recomp_byname.get(pair, None)
                if recomp_addr is not None:
                    batch.match(orig_addr, recomp_addr)

        with db.batch() as batch:
            for thunk in find_import_thunks(orig_bin):
                name = f"{thunk.dll_name}::{thunk.func_name}"
                batch.set_orig(
                    thunk.addr,
                    name=name,
                    type=EntityType.FUNCTION,
                    skip=True,
                    size=thunk.size,
                    ref_orig=thunk.import_addr,
                )

            for thunk in find_import_thunks(recomp_bin):
                name = f"{thunk.dll_name}::{thunk.func_name}"
                batch.set_recomp(
                    thunk.addr,
                    name=name,
                    type=EntityType.FUNCTION,
                    skip=True,
                    size=thunk.size,
                    ref_recomp=thunk.import_addr,
                )

    def _create_thunks(self, db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
        """Create entities for any thunk functions in the image.
        These are the result of an incremental build."""
        with db.batch() as batch:
            for orig_thunk, orig_addr in orig_bin.thunks:
                if not db.orig_used(orig_thunk):
                    batch.set_orig(
                        orig_thunk,
                        type=EntityType.FUNCTION,
                        size=5,
                        ref_orig=orig_addr,
                        skip=True,
                    )

                # We can only match two thunks if we have already matched both
                # their parent entities. There is nothing to compare because
                # they will either be equal or left unmatched. Set skip=True.

            for recomp_thunk, recomp_addr in recomp_bin.thunks:
                if not db.recomp_used(recomp_thunk):
                    batch.set_recomp(
                        recomp_thunk,
                        type=EntityType.FUNCTION,
                        size=5,
                        ref_recomp=recomp_addr,
                    )

    def _match_exports(self, db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
        # invert for name lookup
        orig_exports = {y: x for (x, y) in orig_bin.exports}

        orig_thunks = dict(orig_bin.thunks)
        recomp_thunks = dict(recomp_bin.thunks)

        with db.batch() as batch:
            for recomp_addr, export_name in recomp_bin.exports:
                orig_addr = orig_exports.get(export_name)
                if orig_addr is None:
                    continue

                # Check whether either of the addresses is actually a thunk.
                # This is a quirk of the debug builds. Technically the export
                # *is* the thunk, but it's more helpful to mark the actual function.
                # It could be the case that only one side is a thunk, but we can
                # deal with that.
                if orig_addr in orig_thunks:
                    orig_addr = orig_thunks[orig_addr]

                if recomp_addr in recomp_thunks:
                    recomp_addr = recomp_thunks[recomp_addr]

                batch.match(orig_addr, recomp_addr)

    def _match_vtordisp(self, db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
        """Find each vtordisp function in each image and match them using
        both the displacement values and the thunk address.

        Should be run after matching all other functions because we depend on
        the thunked functions being matched first.

        PDB does not include the `vtordisp{x, y}' name. We could demangle
        the symbol and get it that way, but instead we just set it here."""

        # Build a reverse mapping from the thunked function and displacement in recomp to the vtordisp address.
        recomp_vtor_reverse = {
            (vt.func_addr, vt.displacement): vt for vt in find_vtordisp(recomp_bin)
        }

        with db.batch() as batch:
            for vtor in find_vtordisp(orig_bin):
                # Follow the link to the thunked function.
                # We want the recomp function addr.
                func = db.get_by_orig(vtor.func_addr)
                if func is None or func.recomp_addr is None:
                    continue

                # Now get the recomp vtor reference.
                recomp_vtor = recomp_vtor_reverse.get(
                    (func.recomp_addr, vtor.displacement)
                )
                if recomp_vtor is None:
                    continue

                # Add the vtordisp name here.
                entity = db.get_by_recomp(recomp_vtor.addr)
                if entity is not None and entity.name is not None:
                    new_name = f"{entity.name}`vtordisp{{{recomp_vtor.displacement[0]}, {recomp_vtor.displacement[1]}}}'"
                    batch.set_recomp(recomp_vtor.addr, name=new_name)

                batch.match(vtor.addr, recomp_vtor.addr)

    def _check_vtables(self, db: EntityDb, orig_bin: PEImage):
        """Alert to cases where the recomp vtable is larger than the one in the orig binary.
        We can tell by looking at:
        1. The address of the following vtable in orig, which gives an upper bound on the size.
        2. The pointers in the orig vtable. If any are zero bytes, this is alignment padding between two vtables.
        """
        for match in db.get_matches_by_type(EntityType.VTABLE):
            assert (
                match.name is not None
                and match.orig_addr is not None
                and match.recomp_addr is not None
                and match.size is not None
            )

            next_orig = db.get_next_orig_addr(match.orig_addr)
            if next_orig is None:
                # this vtable is the last annotation in the project
                continue

            orig_size_upper_limit = next_orig - match.orig_addr
            if orig_size_upper_limit < match.size:
                logger.warning(
                    "Recomp vtable is larger than orig vtable for %s",
                    match.name,
                )
                continue

            # TODO: We might want to fix this at the source (cvdump) instead.
            # Any problem will be logged later when we compare the vtable.
            vtable_size = 4 * (min(match.size, orig_size_upper_limit) // 4)
            orig_table = orig_bin.read(match.orig_addr, vtable_size)

            # Check for a gap (null pointer) in the orig vtable.
            # This may or may not be present, but if it is there, we know the vtable
            # on the recomp side is larger.
            if any(addr == 0 for addr, in struct.iter_unpack("<L", orig_table)):
                logger.warning(
                    "Recomp vtable is larger than orig vtable for %s", match.name
                )

    def _compare_vtable(self, match: ReccmpMatch) -> DiffReport:
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

        # We do not use `get_grouped_opcodes()` because we want to show the entire table
        # if there is a diff to display. Otherwise it would be confusing if the table got cut off.
        opcodes = difflib.SequenceMatcher(
            None,
            [x[1] for x in orig_text],
            [x[1] for x in recomp_text],
        ).get_opcodes()

        unified_diff = combined_diff([opcodes], orig_text, recomp_text)

        assert match.name is not None
        return DiffReport(
            match_type=EntityType.VTABLE,
            orig_addr=match.orig_addr,
            recomp_addr=match.recomp_addr,
            name=match.name,
            udiff=unified_diff,
            ratio=ratio,
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

        if match.entity_type == EntityType.FUNCTION:
            best_name = match.best_name()
            assert best_name is not None

            diff_result = self.function_comparator.compare_function(match)
            if diff_result.match_ratio != 1.0:
                grouped_codes = list(get_grouped_opcodes(diff_result.codes, n=10))
                udiff = combined_diff(
                    grouped_codes, diff_result.orig_inst, diff_result.recomp_inst
                )
            else:
                udiff = None

            return DiffReport(
                match_type=EntityType.FUNCTION,
                orig_addr=match.orig_addr,
                recomp_addr=match.recomp_addr,
                name=best_name,
                udiff=udiff,
                ratio=diff_result.match_ratio,
                is_effective_match=diff_result.is_effective_match,
                is_library=match.get("library", False),
            )

        if match.entity_type == EntityType.VTABLE:
            return self._compare_vtable(match)

        return None

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
        return self._db.get_matches_by_type(EntityType.FUNCTION)

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
