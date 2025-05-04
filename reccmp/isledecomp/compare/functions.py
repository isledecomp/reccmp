from dataclasses import dataclass
import difflib
import struct
from typing import Callable
from reccmp.isledecomp.compare.asm.fixes import assert_fixup, find_effective_match
from reccmp.isledecomp.compare.asm.parse import AsmExcerpt, ParseAsm
from reccmp.isledecomp.compare.asm.replacement import create_name_lookup
from reccmp.isledecomp.compare.db import EntityDb, ReccmpMatch
from reccmp.isledecomp.compare.diff import DiffReport, combined_diff
from reccmp.isledecomp.compare.event import ReccmpEvent, ReccmpReportProtocol
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.isledecomp.formats.pe import PEImage
from reccmp.isledecomp.types import EntityType


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

        # TODO: Do something with these sync points
        # TODO: Add abstraction in self.db

        recomp_start_addr = recomp_combined[0][0]
        recomp_end_addr = recomp_combined[-1][0]
        assert recomp_start_addr is not None and recomp_end_addr is not None
        sync_points = self.db.get_lines_in_recomp_range(
            recomp_start_addr, recomp_end_addr
        )

        # TODO: Split into multiple functions

        # TODO: There likely is a more elegant/efficient way than this
        sync_points_monotonous: list[ReccmpMatch] = []
        last_address = 0
        for sync_point in sync_points:
            if sync_point.recomp_addr > last_address:
                sync_points_monotonous.append(sync_point)
                last_address = sync_point.recomp_addr
            else:
                self.report(
                    ReccmpEvent.WRONG_ORDER,
                    sync_point.orig_addr,
                    f"Line annotation '{sync_point.name}' is out of order relative to other line annotations",
                )

        compared_code_parts: list[tuple[AsmExcerpt, AsmExcerpt]] = []

        for sync_point in sync_points_monotonous:
            # Logic:
            # - Find correct line in orig
            # - Find correct line in recomp
            # - Skip if either does not match
            orig_split_index = next(
                (
                    i
                    for i, entry in enumerate(orig_combined)
                    if entry[0] == sync_point.orig_addr
                ),
                None,
            )
            if orig_split_index is None:
                self.report(
                    ReccmpEvent.NO_MATCH,
                    sync_point.orig_addr,
                    "Found no code line corresponding to this original address",
                )
                continue

            recomp_split_index = next(
                (
                    i
                    for i, entry in enumerate(recomp_combined)
                    if entry[0] == sync_point.recomp_addr
                ),
                None,
            )
            if recomp_split_index is None:
                self.report(
                    ReccmpEvent.NO_MATCH,
                    sync_point.orig_addr,
                    f"Found no code line corresponding to recomp address {hex(sync_point.recomp_addr)}. Recompilation may fix this problem.",
                )
                continue

            # Add the block up to the sync point
            compared_code_parts.append(
                (orig_combined[:orig_split_index], recomp_combined[:recomp_split_index])
            )
            # Add the sync point itself as one block
            compared_code_parts.append(
                (
                    orig_combined[orig_split_index : orig_split_index + 1],
                    recomp_combined[recomp_split_index : recomp_split_index + 1],
                )
            )

            # TODO: Ideally, refactor to use immutable lists

            # Remove the added parts from the originals
            # TODO: Does this crash in case this matches the very last entry? We would want an empty list
            orig_combined = orig_combined[orig_split_index + 1 :]
            recomp_combined = recomp_combined[recomp_split_index + 1 :]

        # Append the leftovers (which is everything in case there are no lines markers)
        compared_code_parts.append(
            (
                orig_combined,
                recomp_combined,
            )
        )

        unified_diff = []
        cumulative_ratio = 0.0
        all_mismatches_are_effective_matches = True

        for local_orig_combined, local_recomp_combined in compared_code_parts:

            # Detach addresses from asm lines for the text diff.
            orig_asm = [x[1] for x in local_orig_combined]
            recomp_asm = [x[1] for x in local_recomp_combined]

            diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm, autojunk=False)
            local_ratio = diff.ratio()

            if local_ratio != 1.0:
                # Check whether we can resolve register swaps which are actually
                # perfect matches modulo compiler entropy.
                codes = diff.get_opcodes()
                part_is_effective_match = find_effective_match(
                    codes, orig_asm, recomp_asm
                )
                if not part_is_effective_match:
                    all_mismatches_are_effective_matches = False
                local_unified_diff = combined_diff(
                    diff,
                    [
                        (hex(addr) if addr is not None else "", instr)
                        for addr, instr in local_orig_combined
                    ],
                    [
                        (hex(addr) if addr is not None else "", instr)
                        for addr, instr in local_recomp_combined
                    ],
                    context_size=10,
                )
            else:
                local_unified_diff = []

            unified_diff += local_unified_diff
            cumulative_ratio += local_ratio * (len(orig_asm) + len(recomp_asm))

        total_ratio = cumulative_ratio / total_lines
        is_effective_match_overall = (
            total_ratio <= 0.999 and all_mismatches_are_effective_matches
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
