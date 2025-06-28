# TODO: Rename
from difflib import SequenceMatcher
import functools
from itertools import pairwise
from typing import Iterable, NamedTuple, Sequence


class _IntermediateSequenceMatch(NamedTuple):
    opcodes: list[tuple[str, int, int, int, int]]
    opcode_groups: list[list[tuple[str, int, int, int, int]]]
    total_lines: int
    weighted_match_ratio: float


class SequenceMatchResult(NamedTuple):
    opcodes: list[tuple[str, int, int, int, int]]
    opcode_groups: list[list[tuple[str, int, int, int, int]]]
    match_ratio: float


def offset_opcode(
    group: tuple[str, int, int, int, int], offset_orig: int, offset_recomp: int
) -> tuple[str, int, int, int, int]:
    op, orig_start, orig_end, recomp_start, recomp_end = group
    return (
        op,
        orig_start + offset_orig,
        orig_end + offset_orig,
        recomp_start + offset_recomp,
        recomp_end + offset_recomp,
    )

# TODO: Unit tests

def match_sequences_with_pins(
    a: Sequence[str],
    b: Sequence[str],
    pinned_lines: Iterable[tuple[int, int]],
) -> SequenceMatchResult:
    """
    Finds the differences between two string sequences, where some associations (pins) between
    the lines are known. The result format is compatible with `difflib.SequenceMatcher`.
    """

    def accumulator(
        acc: _IntermediateSequenceMatch, current: tuple[tuple[int, int], tuple[int, int]]
    ):
        (orig_start, recomp_start), (orig_end, recomp_end) = current
        orig_asm_local = a[orig_start:orig_end]
        recomp_asm_local = b[recomp_start:recomp_end]
        current_lines = len(orig_asm_local) + len(recomp_asm_local)

        diff = SequenceMatcher(None, orig_asm_local, recomp_asm_local, autojunk=False)

        offset_opcodes = [
            offset_opcode(opcode, orig_start, recomp_start)
            for opcode in diff.get_opcodes()
        ]
        offset_opcode_groups = [
            [offset_opcode(opcode, orig_start, recomp_start) for opcode in group]
            for group in diff.get_grouped_opcodes(n=10)
        ]

        if len(acc.opcode_groups) == 0:
            merged_opcode_groups = offset_opcode_groups
        elif len(offset_opcode_groups) == 0:
            # This should never happen, just to be sure
            merged_opcode_groups = acc.opcode_groups
        else:
            # Join the groups at the intersection
            acc.opcode_groups[-1] += offset_opcode_groups.pop(0)
            merged_opcode_groups = acc.opcode_groups + offset_opcode_groups

        accumulated_weighted_match_ratio = (
            acc.weighted_match_ratio + max(current_lines, 1) * diff.ratio()
        )

        return _IntermediateSequenceMatch(
            opcodes=acc.opcodes + offset_opcodes,
            opcode_groups=merged_opcode_groups,
            total_lines=acc.total_lines + current_lines,
            weighted_match_ratio=accumulated_weighted_match_ratio,
        )

    # Add the first and last index to the pins so we can iterate with `pairwise()`
    pins_with_first_and_last = [(0, 0)]
    pins_with_first_and_last.extend(pinned_lines)
    pins_with_first_and_last.append((len(a), len(b)))

    result = functools.reduce(
        accumulator,
        pairwise(pins_with_first_and_last),
        _IntermediateSequenceMatch(
            opcodes=[], opcode_groups=[], total_lines=0, weighted_match_ratio=0.0
        ),
    )
    overall_match_ratio = result.weighted_match_ratio / max(result.total_lines, 1)

    return SequenceMatchResult(result.opcodes, result.opcode_groups, overall_match_ratio)
