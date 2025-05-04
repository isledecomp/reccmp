from dataclasses import dataclass
import difflib
import struct
from itertools import pairwise
from typing import Callable, Iterator, NamedTuple
from reccmp.isledecomp.compare.asm.fixes import assert_fixup, find_effective_match
from reccmp.isledecomp.compare.asm.parse import AsmExcerpt, ParseAsm
from reccmp.isledecomp.compare.asm.replacement import create_name_lookup
from reccmp.isledecomp.compare.db import EntityDb, ReccmpMatch
from reccmp.isledecomp.compare.diff import CombinedDiffOutput, DiffReport, combined_diff
from reccmp.isledecomp.compare.event import ReccmpEvent, ReccmpReportProtocol
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.isledecomp.formats.pe import PEImage
from reccmp.isledecomp.types import EntityType


class FunctionPartCompareResult(NamedTuple):
    diff: CombinedDiffOutput
    is_effective_match: bool
    # The match ratio multiplied by the combined number of instructions in orig and recomp
    weighted_match_ratio: float


def create_reloc_lookup(bin_file: PEImage) -> Callable[[int], bool]:
    """Function generator for relocation table lookup"""

    def lookup(addr: int) -> bool:
        return addr > bin_file.imagebase and bin_file.is_relocated_addr(addr)

    return lookup


def create_bin_lookup(bin_file: PEImage) -> Callable[[int], int | None]:
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
    db: EntityDb
    orig_bin: PEImage
    recomp_bin: PEImage
    report: ReccmpReportProtocol
    runid: str
    debug: bool = False

    def __post_init__(self):
        self.orig_sanitize = ParseAsm(
            addr_test=create_reloc_lookup(self.orig_bin),
            name_lookup=create_name_lookup(
                self.db.get_by_orig, create_bin_lookup(self.orig_bin), "orig_addr"
            ),
        )
        self.recomp_sanitize = ParseAsm(
            addr_test=create_reloc_lookup(self.recomp_bin),
            name_lookup=create_name_lookup(
                self.db.get_by_recomp,
                create_bin_lookup(self.recomp_bin),
                "recomp_addr",
            ),
        )

    def _dump_asm(self, orig_combined, recomp_combined):
        """Append the provided assembly output to the debug files"""
        with open(f"orig-{self.runid}.txt", "a", encoding="utf-8") as f:
            for addr, line in orig_combined:
                f.write(f"{addr}: {line}\n")

        with open(f"recomp-{self.runid}.txt", "a", encoding="utf-8") as f:
            for addr, line in recomp_combined:
                f.write(f"{addr}: {line}\n")

    def compare_function(self, match: ReccmpMatch) -> DiffReport:
        # Detect when the recomp function size would cause us to read
        # enough bytes from the original function that we cross into
        # the next annotated function.
        next_orig = self.db.get_next_orig_addr(match.orig_addr)
        if next_orig is not None:
            orig_size = min(next_orig - match.orig_addr, match.size)
        else:
            orig_size = match.size

        orig_raw = self.orig_bin.read(match.orig_addr, orig_size)
        recomp_raw = self.recomp_bin.read(match.recomp_addr, match.size)

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

        orig_combined = self.orig_sanitize.parse_asm(orig_raw, match.orig_addr)
        recomp_combined = self.recomp_sanitize.parse_asm(recomp_raw, match.recomp_addr)

        total_lines = len(orig_combined) + len(recomp_combined)

        if self.debug:
            self._dump_asm(orig_combined, recomp_combined)

        # Check for assert calls only if we expect to find them
        if self.orig_bin.is_debug or self.recomp_bin.is_debug:
            assert_fixup(orig_combined)
            assert_fixup(recomp_combined)

        line_annotations = self._collect_line_annotations(recomp_combined)
        code_split_by_annotations = self._split_code_on_line_annotations(
            orig_combined, recomp_combined, line_annotations
        )

        diffs = [
            self._compare_function_part(orig_block, recomp_block)
            for orig_block, recomp_block in code_split_by_annotations
        ]

        unified_diff = []
        for diff in diffs:
            unified_diff += diff.diff

        total_ratio = sum(diff.weighted_match_ratio for diff in diffs) / total_lines
        is_effective_match_overall = total_ratio <= 0.999 and all(
            diff.is_effective_match for diff in diffs
        )

        best_name = match.best_name()
        assert best_name is not None
        return DiffReport(
            match_type=EntityType.FUNCTION,
            orig_addr=match.orig_addr,
            recomp_addr=match.recomp_addr,
            name=best_name,
            udiff=unified_diff,
            ratio=total_ratio,
            is_effective_match=is_effective_match_overall,
        )

    def _compare_function_part(
        self, orig: AsmExcerpt, recomp: AsmExcerpt
    ) -> FunctionPartCompareResult:
        # Detach addresses from asm lines for the text diff.
        orig_asm = [x[1] for x in orig]
        recomp_asm = [x[1] for x in recomp]

        diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm, autojunk=False)
        local_ratio = diff.ratio()

        if local_ratio != 1.0:
            # Check whether we can resolve register swaps which are actually
            # perfect matches modulo compiler entropy.
            codes = diff.get_opcodes()
            is_effective = find_effective_match(codes, orig_asm, recomp_asm)

            # Convert the addresses to hex string for the diff output
            orig_combined_as_strings = [
                (hex(addr) if addr is not None else "", instr) for addr, instr in orig
            ]
            recomp_combined_as_strings = [
                (hex(addr) if addr is not None else "", instr) for addr, instr in recomp
            ]
            unified_diff = combined_diff(
                diff,
                orig_combined_as_strings,
                recomp_combined_as_strings,
                context_size=10,
            )
        else:
            unified_diff = []
            is_effective = False

        return FunctionPartCompareResult(
            unified_diff,
            is_effective,
            local_ratio * (len(orig) + len(recomp)),
        )

    def _collect_line_annotations(self, recomp: AsmExcerpt) -> list[ReccmpMatch]:
        """
        Finds all `// LINE:` annotations within the given function
        and drops any whose order is not consistent between original and recomp.
        """
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
                    f"Line annotation '{sync_point.name}' is out of order relative to other line annotations",
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
        Contains the first index and last index + 1 in order to facilitate iterating over it.
        """
        split_points: list[tuple[int, int]] = [(0, 0)]

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

        # Add one past the last index to facilitate iterating
        split_points.append((len(orig), len(recomp)))

        return split_points
