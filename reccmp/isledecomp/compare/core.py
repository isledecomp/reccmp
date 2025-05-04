import os
import logging
import difflib
from pathlib import Path
import struct
import uuid
from typing import Iterable, Iterator
from reccmp.isledecomp.compare.functions import FunctionComparator
from reccmp.isledecomp.formats.pe import PEImage
from reccmp.isledecomp.cvdump.demangler import (
    demangle_string_const,
    get_function_arg_string,
)
from reccmp.isledecomp.cvdump import Cvdump, CvdumpAnalysis
from reccmp.isledecomp.parser import DecompCodebase
from reccmp.isledecomp.dir import walk_source_dir
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.compare.event import (
    ReccmpEvent,
    ReccmpReportProtocol,
    reccmp_report_nop,
    create_logging_wrapper,
)
from reccmp.isledecomp.analysis import find_float_consts
from .match_msvc import (
    match_lines,
    match_symbols,
    match_functions,
    match_vtables,
    match_static_variables,
    match_variables,
    match_strings,
)
from .db import EntityDb, ReccmpEntity, ReccmpMatch
from .diff import DiffReport, combined_diff
from .lines import LinesDb


# pylint: disable=too-many-lines


logger = logging.getLogger(__name__)


class Compare:
    # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        orig_bin: PEImage,
        recomp_bin: PEImage,
        pdb_file: Path | str,
        code_dir: Path | str,
        target_id: str | None = None,
    ):
        self.orig_bin = orig_bin
        self.recomp_bin = recomp_bin
        self.pdb_file = str(pdb_file)
        self.code_dir = Path(code_dir)
        if target_id is not None:
            self.target_id = target_id
        else:
            # Assume module name is the base filename of the original binary.
            self.target_id, _ = os.path.splitext(
                os.path.basename(self.orig_bin.filepath)
            )
            self.target_id = self.target_id.upper()
            logger.warning('Assuming id="%s"', self.target_id)
        # Controls whether we dump the asm output to a file
        self.debug: bool = False
        self.runid: str = uuid.uuid4().hex[:8]

        code_files = [Path(p) for p in walk_source_dir(self.code_dir)]
        self._lines_db = LinesDb(code_files)
        self._db = EntityDb()

        # For now, just redirect match alerts to the logger.
        report = create_logging_wrapper(logger)

        self._load_cvdump()
        self._load_markers(report)

        # Match using PDB and annotation data
        match_symbols(self._db, report, truncate=True)
        match_functions(self._db, report, truncate=True)
        match_vtables(self._db, report)
        match_static_variables(self._db, report)
        match_variables(self._db, report)
        match_strings(self._db, report)
        match_lines(self._db, self.cv, self.recomp_bin, report)

        self._match_array_elements()
        # Detect floats first to eliminate potential overlap with string data
        self._find_float_const()
        self._find_original_strings()
        self._match_imports()
        self._match_exports()
        self._match_thunks()
        self._find_vtordisp()
        self._unique_names_for_overloaded_functions()

        self.function_comparator = FunctionComparator(
            self._db, self.orig_bin, self.recomp_bin, report, self.runid, self.debug
        )

    def _load_cvdump(self):
        logger.info("Parsing %s ...", self.pdb_file)
        self.cv = (
            Cvdump(self.pdb_file)
            .lines()
            .globals()
            .publics()
            .symbols()
            .section_contributions()
            .types()
            .run()
        )
        self.cvdump_analysis = CvdumpAnalysis(self.cv)

        # Build the list of entries to insert to the DB.
        # In the rare case we have duplicate symbols for an address, ignore them.
        seen_addrs = set()

        with self._db.batch() as batch:
            for sym in self.cvdump_analysis.nodes:
                # Skip nodes where we have almost no information.
                # These probably came from SECTION CONTRIBUTIONS.
                if sym.name() is None and sym.node_type is None:
                    continue

                # The PDB might contain sections that do not line up with the
                # actual binary. The symbol "__except_list" is one example.
                # In these cases, just skip this symbol and move on because
                # we can't do much with it.
                if not self.recomp_bin.is_valid_section(sym.section):
                    continue

                addr = self.recomp_bin.get_abs_addr(sym.section, sym.offset)
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
                        self.recomp_bin.get_section_extent_by_index(sym.section)
                        - sym.offset
                    )

                if sym.node_type == EntityType.STRING:
                    assert sym.decorated_name is not None
                    string_info = demangle_string_const(sym.decorated_name)
                    if string_info is None:
                        logger.debug(
                            "Could not demangle string symbol: %s", sym.decorated_name
                        )
                        continue

                    # TODO: skip unicode for now. will need to handle these differently.
                    if string_info.is_utf16:
                        continue

                    size = sym.size()
                    assert size is not None

                    raw = self.recomp_bin.read(addr, size)

                    try:
                        # We use the string length reported in the mangled symbol as the
                        # data size, but this is not always accurate with respect to the
                        # null terminator.
                        # e.g. ??_C@_0BA@EFDM@MxObjectFactory?$AA@
                        # reported length: 16 (includes null terminator)
                        # c.f. ??_C@_03DPKJ@enz?$AA@
                        # reported length: 3 (does NOT include terminator)
                        # This will handle the case where the entire string contains "\x00"
                        # because those are distinct from the empty string of length 0.
                        decoded_string = raw.decode("latin1")
                        rstrip_string = decoded_string.rstrip("\x00")

                        # TODO: Hack to exclude a string that contains \x00 bytes
                        # The proper solution is to escape the text for JSON or use
                        # base64 encoding for comparing binary values.
                        # Kicking the can down the road for now.
                        if "\x00" in decoded_string and rstrip_string == "":
                            continue
                        sym.friendly_name = rstrip_string

                    except UnicodeDecodeError:
                        pass

                batch.set_recomp(
                    addr,
                    type=sym.node_type,
                    name=sym.name(),
                    symbol=sym.decorated_name,
                    size=sym.size(),
                )

        for (section, offset), (
            filename,
            line_no,
        ) in self.cvdump_analysis.verified_lines.items():
            addr = self.recomp_bin.get_abs_addr(section, offset)
            self._lines_db.add_line(filename, line_no, addr)

        # The _entry symbol is referenced in the PE header so we get this match for free.
        with self._db.batch() as batch:
            batch.set_recomp(self.recomp_bin.entry, type=EntityType.FUNCTION)
            batch.match(self.orig_bin.entry, self.recomp_bin.entry)

    def _load_markers(self, report: ReccmpReportProtocol = reccmp_report_nop):
        codefiles = list(walk_source_dir(self.code_dir))
        codebase = DecompCodebase(codefiles, self.target_id)

        def orig_bin_checker(addr: int) -> bool:
            return self.orig_bin.is_valid_vaddr(addr)

        # If the address of any annotation would cause an exception,
        # remove it and report an error.
        bad_annotations = codebase.prune_invalid_addrs(orig_bin_checker)

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
        with self._db.batch() as batch:
            for fun in codebase.iter_line_functions():
                batch.set_orig(
                    fun.offset, type=EntityType.FUNCTION, stub=fun.should_skip()
                )

                assert fun.filename is not None
                recomp_addr = self._lines_db.search_line(
                    fun.filename, fun.line_number, fun.end_line
                )

                if recomp_addr is not None:
                    batch.match(fun.offset, recomp_addr)

            for fun in codebase.iter_name_functions():
                batch.set_orig(
                    fun.offset, type=EntityType.FUNCTION, stub=fun.should_skip()
                )

                if fun.name.startswith("?"):
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
                    # TODO: would presumably fail for wchar_t strings
                    orig = self.orig_bin.read_string(string.offset).decode("latin1")
                    string_correct = string.name == orig
                except UnicodeDecodeError:
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
                    name=string.name,
                    type=EntityType.STRING,
                    size=len(string.name),
                )

            for line in codebase.iter_line_symbols():
                batch.set_orig(
                    line.offset,
                    name=line.name,
                    filename=line.filename,
                    line=line.line_number,
                    type=EntityType.LINE,
                )

    def _match_array_elements(self):
        """
        For each matched variable, check whether it is an array.
        If yes, adds a match for all its elements. If it is an array of structs, all fields in that struct are also matched.
        Note that there is no recursion, so an array of arrays would not be handled entirely.
        This step is necessary e.g. for `0x100f0a20` (LegoRacers.cpp).
        """
        seen_recomp = set()
        batch = self._db.batch()

        # Helper function
        def _add_match_in_array(
            name: str, type_id: str, orig_addr: int, recomp_addr: int, max_orig: int
        ):
            # pylint: disable=unused-argument
            # TODO: Previously used scalar_type_pointer(type_id) to set whether this is a pointer
            if recomp_addr in seen_recomp:
                return

            seen_recomp.add(recomp_addr)
            batch.set_recomp(recomp_addr, name=name)
            if orig_addr < max_orig:
                batch.match(orig_addr, recomp_addr)

        # Indexed by recomp addr. Need to preload this data because it is not stored alongside the db rows.
        cvdump_lookup = {x.addr: x for x in self.cvdump_analysis.nodes}

        for match in self._db.get_matches_by_type(EntityType.DATA):
            node = cvdump_lookup.get(match.recomp_addr)
            if node is None or node.data_type is None:
                continue

            if not node.data_type.key.startswith("0x"):
                # scalar type, so clearly not an array
                continue

            data_type = self.cv.types.keys[node.data_type.key.lower()]

            if data_type["type"] != "LF_ARRAY":
                continue

            # Check whether another orig variable appears before the end of the array in recomp.
            # If this happens we can still add all the recomp offsets, but do not attach the orig address
            # where it would extend into the next variable.
            upper_bound = match.orig_addr + match.size
            if (
                next_orig := self._db.get_next_orig_addr(match.orig_addr)
            ) is not None and next_orig < upper_bound:
                logger.warning(
                    "Array variable %s at 0x%x is larger in recomp",
                    match.name,
                    match.orig_addr,
                )
                upper_bound = next_orig

            array_element_type = self.cv.types.get(data_type["array_type"])

            assert node.data_type.members is not None

            for array_element in node.data_type.members:
                orig_element_base_addr = match.orig_addr + array_element.offset
                recomp_element_base_addr = match.recomp_addr + array_element.offset
                if array_element_type.members is None:
                    # If array of scalars
                    _add_match_in_array(
                        f"{match.name}{array_element.name}",
                        array_element_type.key,
                        orig_element_base_addr,
                        recomp_element_base_addr,
                        upper_bound,
                    )

                else:
                    # Else: multidimensional array or array of structs
                    for member in array_element_type.members:
                        _add_match_in_array(
                            f"{match.name}{array_element.name}.{member.name}",
                            array_element_type.key,
                            orig_element_base_addr + member.offset,
                            recomp_element_base_addr + member.offset,
                            upper_bound,
                        )

        batch.commit()

    def _find_original_strings(self):
        """Go to the original binary and look for the specified string constants
        to find a match. This is a (relatively) expensive operation so we only
        look at strings that we have not already matched via a STRING annotation."""
        # Release builds give each de-duped string a symbol so they are easy to find and match.
        for string in self._db.get_unmatched_strings():
            addr = self.orig_bin.find_string(string.encode("latin1"))
            if addr is None:
                escaped = repr(string)
                logger.debug("Failed to find this string in the original: %s", escaped)
                continue

            self._db.match_string(addr, string)

        def is_real_string(s: str) -> bool:
            """Heuristic to ignore values that only look like strings.
            This is mostly about short strings (len <= 4) that could be byte or word values.
            """
            # 0x10 is the MSB of the address space for DLLs (LEGO1), so this is a pointer
            if len(s) == 0 or "\x10" in s:
                return False

            # assert(0) is common
            if len(s) == 1 and s[0] != "0":
                return False

            # Hack because str.isprintable() will fail on strings with newlines or tabs
            if len(s) <= 4 and "\\x" in repr(s):
                return False

            return True

        # Debug builds do not de-dupe the strings, so we need to find them via brute force scan.
        # We could try to match the string addrs if there is only one in orig and recomp.
        # When we sanitize the asm, the result is the same regardless.
        if self.orig_bin.is_debug:
            with self._db.batch() as batch:
                for addr, string in self.orig_bin.iter_string("latin1"):
                    if is_real_string(string):
                        batch.insert_orig(
                            addr, type=EntityType.STRING, name=string, size=len(string)
                        )

                for addr, string in self.recomp_bin.iter_string("latin1"):
                    if is_real_string(string):
                        batch.insert_recomp(
                            addr, type=EntityType.STRING, name=string, size=len(string)
                        )

    def _find_float_const(self):
        """Add floating point constants in each binary to the database.
        We are not matching anything right now because these values are not
        deduped like strings."""
        with self._db.batch() as batch:
            for addr, size, float_value in find_float_consts(self.orig_bin):
                batch.insert_orig(
                    addr, type=EntityType.FLOAT, name=str(float_value), size=size
                )

            for addr, size, float_value in find_float_consts(self.recomp_bin):
                batch.insert_recomp(
                    addr, type=EntityType.FLOAT, name=str(float_value), size=size
                )

    def _match_imports(self):
        """We can match imported functions based on the DLL name and
        function symbol name."""
        orig_byaddr = {
            addr: (dll.upper(), name) for (dll, name, addr) in self.orig_bin.imports
        }
        recomp_byname = {
            (dll.upper(), name): addr for (dll, name, addr) in self.recomp_bin.imports
        }

        with self._db.batch() as batch:
            for dll, name, addr in self.orig_bin.imports:
                import_name = f"{dll.upper()}:{name}"
                batch.set_orig(
                    addr,
                    name=f"__imp__{name}",
                    import_name=import_name,
                    size=4,
                    type=EntityType.IMPORT,
                )

            for dll, name, addr in self.recomp_bin.imports:
                # TODO: recomp imports should already have a name from the PDB
                # but set it anyway to avoid problems later.
                import_name = f"{dll.upper()}:{name}"
                batch.set_recomp(
                    addr,
                    name=f"__imp__{name}",
                    import_name=import_name,
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

    def _match_thunks(self):
        """Thunks are (by nature) matched by indirection. If a thunk from orig
        points at a function we have already matched, we can find the matching
        thunk in recomp because it points to the same place."""

        # Mark all recomp thunks first. This allows us to use their name
        # when we sanitize the asm.
        for recomp_thunk, recomp_addr in self.recomp_bin.thunks:
            recomp_func = self._db.get_by_recomp(recomp_addr)
            if recomp_func is None:
                continue

            assert recomp_func.name is not None
            self._db.create_recomp_thunk(recomp_thunk, recomp_func.name)

        # Thunks may be non-unique, so use a list as dict value when
        # inverting the list of tuples from self.recomp_bin.
        recomp_thunks: dict[int, list[int]] = {}
        for thunk_addr, func_addr in self.recomp_bin.thunks:
            recomp_thunks.setdefault(func_addr, []).append(thunk_addr)

        # Now match the thunks from orig where we can.
        for orig_thunk, orig_addr in self.orig_bin.thunks:
            orig_func = self._db.get_by_orig(orig_addr)
            if orig_func is None or orig_func.recomp_addr is None:
                continue

            # Check whether the thunk destination is a matched symbol
            if orig_func.recomp_addr not in recomp_thunks:
                assert orig_func.name is not None
                self._db.create_orig_thunk(orig_thunk, orig_func.name)
                continue

            # If there are multiple thunks, they are already in v.addr order.
            # Pop the earliest one and match it.
            recomp_thunk = recomp_thunks[orig_func.recomp_addr].pop(0)
            if len(recomp_thunks[orig_func.recomp_addr]) == 0:
                del recomp_thunks[orig_func.recomp_addr]

            self._db.set_function_pair(orig_thunk, recomp_thunk)

            # Don't compare thunk functions for now. The comparison isn't
            # "useful" in the usual sense. We are only looking at the
            # bytes of the jmp instruction and not the larger context of
            # where this function is. Also: these will always match 100%
            # because we are searching for a match to register this as a
            # function in the first place.
            self._db.skip_compare(orig_thunk)

    def _match_exports(self):
        # invert for name lookup
        orig_exports = {y: x for (x, y) in self.orig_bin.exports}

        for recomp_addr, export_name in self.recomp_bin.exports:
            orig_addr = orig_exports.get(export_name)
            if orig_addr is None:
                continue

            try:
                # Check whether either of the addresses is actually a thunk.
                # This is a quirk of the debug builds. Technically the export
                # *is* the thunk, but it's more helpful to mark the actual function.
                # It could be the case that only one side is a thunk, but we can
                # deal with that.
                rel_addr: int
                (opcode, rel_addr) = struct.unpack(
                    "<Bl", self.recomp_bin.read(recomp_addr, 5)
                )
                if opcode == 0xE9:
                    recomp_addr += 5 + rel_addr

                (opcode, rel_addr) = struct.unpack(
                    "<Bl", self.orig_bin.read(orig_addr, 5)
                )
                if opcode == 0xE9:
                    orig_addr += 5 + rel_addr
            except ValueError:
                # Bail out if there's a problem with struct.unpack
                continue

            if self._db.set_pair_tentative(orig_addr, recomp_addr):
                logger.debug("Matched export %s", repr(export_name))

    def _find_vtordisp(self):
        """If there are any cases of virtual inheritance, we can read
        through the vtables for those classes and find the vtable thunk
        functions (vtordisp).

        Our approach is this: walk both vtables and check where we have a
        vtordisp in the recomp table. Inspect the function at that vtable
        position (in both) and check whether we jump to the same function.

        One potential pitfall here is that the virtual displacement could
        differ between the thunks. We are not (yet) checking for this, so the
        result is that the vtable will appear to match but we will have a diff
        on the thunk in our regular function comparison.

        We could do this differently and check only the original vtable,
        construct the name of the vtordisp function and match based on that."""

        for match in self._db.get_matches_by_type(EntityType.VTABLE):
            assert (
                match.name is not None
                and match.orig_addr is not None
                and match.recomp_addr is not None
                and match.size is not None
            )
            # We need some method of identifying vtables that
            # might have thunks, and this ought to work okay.
            if "{for" not in match.name:
                continue

            next_orig = self._db.get_next_orig_addr(match.orig_addr)
            assert next_orig is not None
            orig_upper_size_limit = next_orig - match.orig_addr
            if orig_upper_size_limit < match.size:
                # This could happen in debug builds due to code changes between BETA10 and LEGO1,
                # but we have not seen it yet as of 2024-08-28.
                logger.warning(
                    "Recomp vtable is larger than orig vtable for %s",
                    match.name,
                )

            # TODO: We might want to fix this at the source (cvdump) instead.
            # Any problem will be logged later when we compare the vtable.
            vtable_size = 4 * (min(match.size, orig_upper_size_limit) // 4)
            orig_table = self.orig_bin.read(match.orig_addr, vtable_size)
            recomp_table = self.recomp_bin.read(match.recomp_addr, vtable_size)

            raw_addrs = zip(
                [t for (t,) in struct.iter_unpack("<L", orig_table)],
                [t for (t,) in struct.iter_unpack("<L", recomp_table)],
            )

            # Now walk both vtables looking for thunks.
            for orig_addr, recomp_addr in raw_addrs:
                if orig_addr == 0:
                    # This happens in debug builds due to code changes between BETA10 and LEGO1.
                    # Note that there is a risk of running into the next vtable if there is no gap in between,
                    # which we cannot protect against at the moment.
                    logger.warning(
                        "Recomp vtable is larger than orig vtable for %s", match.name
                    )
                    break

                if self._db.is_vtordisp(recomp_addr):
                    self._match_vtordisp_in_vtable(orig_addr, recomp_addr)

    def _match_vtordisp_in_vtable(self, orig_addr, recomp_addr):
        thunk_fn = self.get_by_recomp(recomp_addr)
        assert thunk_fn is not None

        # Read the function bytes here.
        # In practice, the adjuster thunk will be under 16 bytes.
        # If we have thunks of unequal size, we can still tell whether they are thunking
        # the same function by grabbing the JMP instruction at the end.
        thunk_presumed_size = max(thunk_fn.size, 16)

        # Strip off MSVC padding 0xcc bytes.
        # This should be safe to do; it is highly unlikely that
        # the MSB of the jump displacement would be 0xcc. (huge jump)
        orig_thunk_bin = self.orig_bin.read(orig_addr, thunk_presumed_size).rstrip(
            b"\xcc"
        )

        recomp_thunk_bin = self.recomp_bin.read(
            recomp_addr, thunk_presumed_size
        ).rstrip(b"\xcc")

        # Read jump opcode and displacement (last 5 bytes)
        (orig_jmp, orig_disp) = struct.unpack("<Bi", orig_thunk_bin[-5:])
        (recomp_jmp, recomp_disp) = struct.unpack("<Bi", recomp_thunk_bin[-5:])

        # Make sure it's a JMP
        if orig_jmp != 0xE9 or recomp_jmp != 0xE9:
            logger.warning(
                "Not a jump in vtordisp at (0x%x, 0x%x)", orig_addr, recomp_addr
            )
            return

        # Calculate jump destination from the end of the JMP instruction
        # i.e. the end of the function
        orig_actual = orig_addr + len(orig_thunk_bin) + orig_disp
        recomp_actual = recomp_addr + len(recomp_thunk_bin) + recomp_disp

        # If they are thunking the same function, then this must be a match.
        if self.is_pointer_match(orig_actual, recomp_actual):
            if len(orig_thunk_bin) != len(recomp_thunk_bin):
                logger.warning(
                    "Adjuster thunk %s (0x%x) is not exact",
                    thunk_fn.name,
                    orig_addr,
                )
            # Use `tentative` because vtordisps can be shared between different vtables.
            # We get a lot of `address not unique!` debug logs otherwise
            self._db.set_function_pair_tentative(orig_addr, recomp_addr)

    def _unique_names_for_overloaded_functions(self):
        """Our asm sanitize will use the "friendly" name of a function.
        Overloaded functions will all have the same name. This function detects those
        cases and gives each one a unique name in the db."""
        repeat_names: dict[str, list[tuple[int, str | None]]] = {}

        # Select addresses and symbols for all repeated function names
        for recomp_addr, name, symbol in self._db.sql.execute(
            """SELECT recomp_addr, json_extract(kvstore,'$.name') as name, json_extract(kvstore,'$.symbol')
            from entities where name in (
                select json_extract(kvstore,'$.name') as name from entities
                where json_extract(kvstore,'$.type') = ?
                group by name having count(name) > 1
            )""",
            (EntityType.FUNCTION,),
        ):
            # TODO: Thunk's link to the original function is lost once the record is created.
            if "Thunk of" in name:
                continue

            repeat_names.setdefault(name, []).append((recomp_addr, symbol))

        updates = {}

        for name, items in repeat_names.items():
            for i, (recomp_addr, symbol) in enumerate(items, start=1):
                # Just number it to start, in case we don't have a symbol.
                new_name = f"{name}({i})"

                if symbol is not None:
                    dm_args = get_function_arg_string(symbol)
                    if dm_args is not None:
                        new_name = f"{name}{dm_args}"

                updates[recomp_addr] = new_name

        self._db.sql.executemany(
            "UPDATE entities SET kvstore = json_set(kvstore,'$.computed_name',?) WHERE recomp_addr = ?",
            ((name, addr) for addr, name in updates.items()),
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
                return f"({orig} / {recomp})  :  {m.name}"

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

        # n=100: Show the entire table if there is a diff to display.
        # Otherwise it would be confusing if the table got cut off.

        sm = difflib.SequenceMatcher(
            None,
            [x[1] for x in orig_text],
            [x[1] for x in recomp_text],
        )

        unified_diff = combined_diff(sm, orig_text, recomp_text, context_size=100)

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
            return self.function_comparator.compare_function(match)

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

    def compare_variables(self):
        pass

    def compare_pointers(self):
        pass

    def compare_strings(self):
        pass

    def compare_vtables(self) -> Iterable[DiffReport]:
        for match in self.get_vtables():
            diff = self._compare_match(match)
            if diff is not None:
                yield diff
