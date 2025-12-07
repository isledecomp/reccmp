from datetime import datetime
from dataclasses import dataclass
from functools import cache
import struct
from itertools import pairwise
from typing import Callable, Iterator, NamedTuple
from reccmp.isledecomp.compare.lines import LinesDb
from reccmp.isledecomp.difflib import DiffOpcode
from reccmp.isledecomp.compare.pinned_sequences import SequenceMatcherWithPins
from reccmp.isledecomp.compare.asm.fixes import assert_fixup, find_effective_match
from reccmp.isledecomp.compare.asm.parse import AsmExcerpt, ParseAsm
from reccmp.isledecomp.compare.asm.replacement import (
    AddrLookupProtocol,
    create_name_lookup,
)
from reccmp.isledecomp.compare.db import EntityDb, ReccmpMatch
from reccmp.isledecomp.compare.event import ReccmpEvent, ReccmpReportProtocol
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.isledecomp.formats import Image, PEImage


class FunctionCompareResult(NamedTuple):
    codes: list[DiffOpcode]
    orig_inst: list[tuple[str, str]]
    recomp_inst: list[tuple[str, str]]
    is_effective_match: bool
    match_ratio: float


def timestamp_string() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def has_asserts(image: Image) -> bool:
    if isinstance(image, PEImage):
        return image.is_debug

    return False


def create_valid_addr_lookup(
    db_getter: AddrLookupProtocol,
    is_recomp: bool,
    bin_file: Image,
) -> Callable[[int], bool]:
    """
    Function generator for a lookup whether an address from a call is valid
    (either a relocation or pointing to something else we know, like a global variable)
    """

    @cache
    def lookup(addr: int) -> bool:
        # Check if in relocation table
        if addr > bin_file.imagebase and bin_file.is_relocated_addr(addr):
            return True

        # Check whether the address points to valid data
        entity = db_getter(addr, exact=False)
        if entity is None:
            return False
        base_addr = entity.recomp_addr if is_recomp else entity.orig_addr
        if base_addr is None:
            # should never happen
            return False

        address_is_contained_in_entity = addr <= base_addr + entity.size
        return address_is_contained_in_entity

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
    runid: str = timestamp_string()
    debug: bool = False
    is_32bit: bool = True

    def __post_init__(self):
        self.orig_sanitize = ParseAsm(
            addr_test=create_valid_addr_lookup(
                self.db.get_by_orig, False, self.orig_bin
            ),
            name_lookup=create_name_lookup(
                self.db.get_by_orig, create_bin_lookup(self.orig_bin), "orig_addr"
            ),
            is_32bit=self.is_32bit,
        )
        self.recomp_sanitize = ParseAsm(
            addr_test=create_valid_addr_lookup(
                self.db.get_by_recomp, True, self.recomp_bin
            ),
            name_lookup=create_name_lookup(
                self.db.get_by_recomp,
                create_bin_lookup(self.recomp_bin),
                "recomp_addr",
            ),
            is_32bit=self.is_32bit,
        )

    def _dump_asm(self, orig_combined, recomp_combined):
        """Append the provided assembly output to the debug files"""
        with open(f"reccmp-{self.runid}-orig.txt", "a", encoding="utf-8") as f:
            for addr, line in orig_combined:
                if addr:
                    f.write(f"{addr:8x}: {line}\n")
                else:
                    f.write(f"        : {line}\n")

        with open(f"reccmp-{self.runid}-recomp.txt", "a", encoding="utf-8") as f:
            for addr, line in recomp_combined:
                if addr:
                    f.write(f"{addr:8x}: {line}\n")
                else:
                    f.write(f"        : {line}\n")

    def _source_ref_of_recomp_addr(self, recomp_addr: int | None) -> str | None:
        if recomp_addr is None:
            return None
        path_line_pair = self.lines_db.find_line_of_recomp_address(recomp_addr)
        if path_line_pair is None:
            return None
        return f"{path_line_pair[0].name}:{path_line_pair[1]}"

    def compare_function(self, match: ReccmpMatch) -> FunctionCompareResult:
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

        if self.debug:
            self._dump_asm(orig_combined, recomp_combined)

        # Check for assert calls only if we expect to find them
        if has_asserts(self.orig_bin):
            assert_fixup(orig_combined)

        if has_asserts(self.recomp_bin):
            assert_fixup(recomp_combined)

        line_annotations = self._collect_line_annotations(recomp_combined)

        split_points = self._compute_split_points(
            orig_combined, recomp_combined, line_annotations
        )

        return self._compare_function_assembly(
            orig_combined, recomp_combined, split_points
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
    ) -> FunctionCompareResult:
        # Detach addresses from asm lines for the text diff.
        orig_asm = [x[1] for x in orig]
        recomp_asm = [x[1] for x in recomp]

        diff = SequenceMatcherWithPins(orig_asm, recomp_asm, split_points)

        if diff.ratio() != 1.0:
            # Check whether we can resolve register swaps which are actually
            # perfect matches modulo compiler entropy.
            is_effective = find_effective_match(
                diff.get_opcodes(), orig_asm, recomp_asm
            )
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

        return FunctionCompareResult(
            codes=diff.get_opcodes(),
            orig_inst=orig_for_printing,
            recomp_inst=recomp_for_printing,
            is_effective_match=is_effective,
            match_ratio=diff.ratio(),
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
