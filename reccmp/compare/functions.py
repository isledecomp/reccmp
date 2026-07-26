from dataclasses import dataclass
from functools import cache
import struct
from itertools import pairwise
from typing import Callable, Iterator
from reccmp.compare.lines import LinesDb
from reccmp.compare.pinned_sequences import SequenceMatcherWithPins
from reccmp.compare.asm.fixes import assert_fixup, find_effective_match
from reccmp.compare.asm.instgen import SectionType
from reccmp.compare.asm.parse import AsmExcerpt, ParseAsm
from reccmp.compare.asm.refine import OperandRefiner
from reccmp.compare.asm.replacement import (
    create_candidate_lookup,
    create_name_lookup,
)
from reccmp.compare.db import EntityDb, ReccmpMatch
from reccmp.compare.diff import EntityCompareResult, RawDiffOutput
from reccmp.compare.event import ReccmpEvent, ReccmpReportProtocol
from reccmp.cvdump.types import CvdumpTypesParser
from reccmp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.formats import Image, PEImage
from reccmp.types import ImageId


def has_asserts(image: Image) -> bool:
    if isinstance(image, PEImage):
        return image.is_debug

    return False


def create_valid_addr_lookup(
    db: EntityDb,
    image_id: ImageId,
    bin_file: Image,
) -> Callable[[int], bool]:
    """
    Function generator for a lookup whether an address from a call is valid
    (either a relocation or pointing to something else we know, like a global variable)
    """
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    @cache
    def lookup(addr: int) -> bool:
        # Check if in relocation table
        if addr > bin_file.imagebase and bin_file.is_relocated_addr(addr):
            return True

        return db.intersects(image_id, addr)

    return lookup


def create_bin_lookup(bin_file: Image) -> Callable[[int], int | None]:
    """Function generator to read a pointer from the bin file"""

    def lookup(addr: int) -> int | None:
        try:
            (ptr,) = struct.unpack("<L", bin_file.read(addr, 4))
            return ptr
        except (struct.error, InvalidVirtualAddressError, InvalidVirtualReadError):
            return None

    return lookup


@dataclass
class FunctionComparator:
    # pylint: disable=too-many-instance-attributes
    db: EntityDb
    lines_db: LinesDb
    orig_bin: Image
    recomp_bin: Image
    report: ReccmpReportProtocol
    types: CvdumpTypesParser
    is_32bit: bool = True

    def __post_init__(self):
        self.orig_sanitize = ParseAsm(
            addr_test=create_valid_addr_lookup(self.db, ImageId.ORIG, self.orig_bin),
            name_lookup=create_name_lookup(
                self.db,
                ImageId.ORIG,
                create_bin_lookup(self.orig_bin),
                self.types.get_name_for_offset,
            ),
            is_32bit=self.is_32bit,
        )
        self.recomp_sanitize = ParseAsm(
            addr_test=create_valid_addr_lookup(
                self.db, ImageId.RECOMP, self.recomp_bin
            ),
            name_lookup=create_name_lookup(
                self.db,
                ImageId.RECOMP,
                create_bin_lookup(self.recomp_bin),
                self.types.get_name_for_offset,
            ),
            is_32bit=self.is_32bit,
        )
        self.orig_candidates = create_candidate_lookup(self.db, ImageId.ORIG)
        self.recomp_candidates = create_candidate_lookup(self.db, ImageId.RECOMP)

    def _source_ref_of_recomp_addr(self, recomp_addr: int | None) -> str | None:
        if recomp_addr is None:
            return None
        path_line_pair = self.lines_db.find_line_of_recomp_address(recomp_addr)
        if path_line_pair is None:
            return None
        return f"{path_line_pair[0].name}:{path_line_pair[1]}"

    def compare_function(self, match: ReccmpMatch) -> EntityCompareResult:
        # Detect when the recomp function size would cause us to read
        # enough bytes from the original function that we cross into
        # the next annotated function.
        orig_size = match.size(ImageId.ORIG)
        recomp_size = match.size(ImageId.RECOMP)

        if orig_size is None:
            assert recomp_size is not None
            orig_max = match.max_size(ImageId.ORIG)
            if orig_max is not None:
                orig_size = min(orig_max, recomp_size)
            else:
                orig_size = recomp_size

        assert orig_size is not None and recomp_size is not None

        orig_raw = self.orig_bin.read(match.orig_addr, orig_size)
        recomp_raw = self.recomp_bin.read(match.recomp_addr, recomp_size)

        # It's unlikely that a function other than an adjuster thunk would
        # start with a SUB instruction, so alert to a possible wrong
        # annotation here.
        # There's probably a better place to do this, but we're reading
        # the function bytes here already.
        try:
            if orig_raw[0] == 0x2B and recomp_raw[0] != 0x2B:
                self.report(
                    ReccmpEvent.GENERAL_WARNING,
                    match.orig_addr,
                    f"Possible thunk ({match.name})",
                )
        except IndexError:
            pass

        orig_combined, recomp_combined = self._parse_asm_with_shared_tables(
            match, orig_raw, recomp_raw
        )

        # Check for assert calls only if we expect to find them
        if has_asserts(self.orig_bin):
            assert_fixup(orig_combined)

        if has_asserts(self.recomp_bin):
            assert_fixup(recomp_combined)

        line_annotations = self._collect_line_annotations(recomp_combined)

        split_points = self._compute_split_points(
            orig_combined, recomp_combined, line_annotations
        )

        refiner = OperandRefiner(
            orig_candidates=self.orig_candidates,
            recomp_candidates=self.recomp_candidates,
            orig_start=match.orig_addr,
            recomp_start=match.recomp_addr,
            # Strictly interior to the function in both images. Anything
            # past the last byte may belong to a different neighbor
            # function in each image.
            self_reach=min(orig_size, recomp_size),
        )

        return self._compare_function_assembly(
            orig_combined, recomp_combined, split_points, refiner
        )

    def _parse_asm_with_shared_tables(
        self, match: ReccmpMatch, orig_raw: bytes, recomp_raw: bytes
    ) -> tuple[AsmExcerpt, AsmExcerpt]:
        """Disassemble and sanitize both sides of the match.

        A jump or data table is only detected once we disassemble the
        instruction that reads it. If that instruction comes after the
        table, the table bytes have already been read as junk code, and
        the junk differs between the images (the table contents are
        relocated), or one side even stops early on an undecodable byte.
        The result is a diff mismatch on code that is not actually
        different.

        If the two sides disagree on the section layout, share the table
        locations (which are function-relative) between the sides and
        re-parse, so both get the chance to split their sections in the
        same spot. Keep the result only if the sides converge on the same
        layout."""
        orig_combined = self.orig_sanitize.parse_asm(orig_raw, match.orig_addr)
        recomp_combined = self.recomp_sanitize.parse_asm(recomp_raw, match.recomp_addr)

        if self.orig_sanitize.last_layout == self.recomp_sanitize.last_layout or (
            not self.orig_sanitize.last_tables and not self.recomp_sanitize.last_tables
        ):
            return (orig_combined, recomp_combined)

        tables = (self.orig_sanitize.last_tables, self.recomp_sanitize.last_tables)
        for _ in range(3):
            # Merge the tables detected by each side. If both sides claim
            # the same location, prefer the jump table: it is detected
            # from the more specific instruction pattern.
            seeds: dict[int, SectionType] = {}
            for side in tables:
                for rel_addr, type_ in side.items():
                    if seeds.get(rel_addr) != SectionType.ADDR_TAB:
                        seeds[rel_addr] = type_

            orig_combined = self.orig_sanitize.parse_asm(
                orig_raw, match.orig_addr, table_seeds=seeds
            )
            recomp_combined = self.recomp_sanitize.parse_asm(
                recomp_raw, match.recomp_addr, table_seeds=seeds
            )

            new_tables = (
                self.orig_sanitize.last_tables,
                self.recomp_sanitize.last_tables,
            )
            if new_tables == tables:
                break

            tables = new_tables

        if self.orig_sanitize.last_layout == self.recomp_sanitize.last_layout:
            return (orig_combined, recomp_combined)

        # The sides did not converge: the code is presumably really
        # different. Restore the unseeded parse.
        return (
            self.orig_sanitize.parse_asm(orig_raw, match.orig_addr),
            self.recomp_sanitize.parse_asm(recomp_raw, match.recomp_addr),
        )

    @staticmethod
    def _print_recomp_instruction(
        instruction: str, *, source_ref: str | None, is_pinned: bool
    ) -> str:
        match source_ref, is_pinned:
            case None, _:
                # cannot be pinned if it has no source reference
                return instruction
            case source_ref_str, False:
                return f"{instruction} \t({source_ref_str})"
            case source_ref_str, True:
                return f"{instruction} \t({source_ref_str}, pinned)"
            case _:
                # Unreachable, but mypy doesn't understand
                assert False

    def _compare_function_assembly(
        self,
        orig: AsmExcerpt,
        recomp: AsmExcerpt,
        split_points: list[tuple[int, int]],
        refiner: OperandRefiner,
    ) -> EntityCompareResult:
        # Detach addresses from asm lines for the text diff.
        orig_asm = [x[1] for x in orig]
        recomp_asm = [x[1] for x in recomp]

        diff = SequenceMatcherWithPins(orig_asm, recomp_asm, split_points)
        codes = diff.get_opcodes()
        ratio = diff.ratio()

        if ratio != 1.0:
            # Some of the mismatching line pairs may differ only in
            # operands that refer to the same thing on both sides.
            refined = refiner.refine(
                orig,
                recomp,
                codes,
                self.orig_sanitize.op_records,
                self.recomp_sanitize.op_records,
            )
            if refined is not None:
                recomp = refined.recomp
                recomp_asm = [x[1] for x in recomp]
                codes = refined.opcodes

                # The refinement turns mismatching pairs into matches and
                # moves nothing else, so the ratio follows directly from
                # the patched opcodes. (2*matches / total lines, as in
                # difflib.SequenceMatcher.ratio)
                total = len(orig_asm) + len(recomp_asm)
                matched = sum(i2 - i1 for tag, i1, i2, _, _ in codes if tag == "equal")
                ratio = 2 * matched / total if total > 0 else 1.0

        if ratio != 1.0:
            # Check whether we can resolve register swaps which are actually
            # perfect matches modulo compiler entropy.
            is_effective = find_effective_match(codes, orig_asm, recomp_asm)
        else:
            is_effective = False

        # Convert the addresses to hex string for the diff output
        orig_for_printing = [
            (hex(addr) if addr is not None else "", instr) for addr, instr in orig
        ]

        recomp_for_printing = [
            (
                hex(addr) if addr is not None else "",
                self._print_recomp_instruction(
                    instruction,
                    source_ref=self._source_ref_of_recomp_addr(addr),
                    is_pinned=any(
                        recomp_addr == line_index for _, recomp_addr in split_points
                    ),
                ),
            )
            for line_index, (addr, instruction) in enumerate(recomp)
        ]

        return EntityCompareResult(
            diff=RawDiffOutput(
                codes=codes,
                orig_inst=orig_for_printing,
                recomp_inst=recomp_for_printing,
            ),
            is_effective_match=is_effective,
            match_ratio=ratio,
        )

    def _collect_line_annotations(self, recomp: AsmExcerpt) -> list[ReccmpMatch]:
        """
        Finds all `// LINE:` annotations within the given function
        and drops any whose order is not consistent between original and recomp.
        """
        if len(recomp) == 0:
            return []

        recomp_start_addr = recomp[0][0]
        recomp_end_addr = recomp[-1][0]
        assert recomp_start_addr is not None and recomp_end_addr is not None
        line_annotations = self.db.get_lines_in_recomp_range(
            recomp_start_addr, recomp_end_addr
        )

        # This is a naive/greedy algorithm to remove the non-monotonous entries.
        # There likely is a "better" way to do this, in the sense that the smallest number
        # of entries is removed.
        line_annotations_monotonous: list[ReccmpMatch] = []
        last_address = 0
        for sync_point in line_annotations:
            if sync_point.recomp_addr > last_address:
                line_annotations_monotonous.append(sync_point)
                last_address = sync_point.recomp_addr
            else:
                self.report(
                    ReccmpEvent.WRONG_ORDER,
                    sync_point.orig_addr,
                    f"Line annotation '{sync_point.name}' is out of order relative to other line annotations.",
                )

        return line_annotations_monotonous

    def _split_code_on_line_annotations(
        self,
        orig_combined: AsmExcerpt,
        recomp_combined: AsmExcerpt,
        line_annotations: list[ReccmpMatch],
    ) -> Iterator[tuple[AsmExcerpt, AsmExcerpt]]:
        """
        For each given `// LINE:` annotation, splits the code into the part before,
        the annotated line, and the part after it.
        """
        split_points = self._compute_split_points(
            orig_combined, recomp_combined, line_annotations
        )

        for (orig_start, recomp_start), (orig_end, recomp_end) in pairwise(
            split_points
        ):
            yield (
                orig_combined[orig_start:orig_end],
                recomp_combined[recomp_start:recomp_end],
            )

    def _compute_split_points(
        self, orig: AsmExcerpt, recomp: AsmExcerpt, line_annotations: list[ReccmpMatch]
    ) -> list[tuple[int, int]]:
        """
        Computes the index pairs into `orig` and `recomp`
        that correspond to the line annotations given in `line_annotations`.
        """
        split_points: list[tuple[int, int]] = []

        for line_annotation in line_annotations:
            orig_split_index = next(
                (
                    i
                    for i, entry in enumerate(orig)
                    if entry[0] == line_annotation.orig_addr
                ),
                None,
            )
            if orig_split_index is None:
                self.report(
                    ReccmpEvent.NO_MATCH,
                    line_annotation.orig_addr,
                    "Found no code line corresponding to this original address",
                )
                continue

            recomp_split_index = next(
                (
                    i
                    for i, entry in enumerate(recomp)
                    if entry[0] == line_annotation.recomp_addr
                ),
                None,
            )
            if recomp_split_index is None:
                self.report(
                    ReccmpEvent.NO_MATCH,
                    line_annotation.orig_addr,
                    f"Found no code line corresponding to recomp address {hex(line_annotation.recomp_addr)}. Recompilation may fix this problem.",
                )
                continue

            split_points.append((orig_split_index, recomp_split_index))
            split_points.append((orig_split_index + 1, recomp_split_index + 1))

        return split_points
