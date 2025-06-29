from difflib import SequenceMatcher
import functools
from itertools import pairwise
import itertools
from typing import Iterable, NamedTuple, Sequence


class _IntermediateSequenceMatch(NamedTuple):
    opcodes: list[tuple[str, int, int, int, int]] = []
    total_lines: int = 0
    weighted_match_ratio: float = 0.0


class SequenceMatcherWithPins:
    """
    Finds the differences between two string sequences, where some associations (pins) between
    the lines are known. The result format is compatible with `difflib.SequenceMatcher`.

    Note that `pinned_lines` must consist of non-decreasing, valid indices into `a` and `b`.
    """

    def __init__(
        self,
        a: Sequence[str],
        b: Sequence[str],
        pinned_lines: Iterable[tuple[int, int]],
    ):
        def accumulator(
            acc: _IntermediateSequenceMatch,
            current: tuple[tuple[int, int], tuple[int, int]],
        ):
            """Matches the block specified by `current` and updates the intermediate information in `acc`."""

            (a_start, b_start), (a_end, b_end) = current
            if a_start > a_end or b_start > b_end:
                # If this were a library, we could log a warning and try to recover.
                # However, in the present case, this is just a failsafe
                # since the monotony is verified and logged elsewhere.
                raise ValueError(
                    f"The provided pinned lines {pinned_lines} are not monotonous."
                )

            a_block = a[a_start:a_end]
            b_block = b[b_start:b_end]
            num_lines_in_block = len(a_block) + len(b_block)

            diff = SequenceMatcher(None, a_block, b_block, autojunk=False)

            # Offset the opcodes so they apply to `a` and `b` instead of `a_block` and `b_block`
            updated_opcodes = acc.opcodes + [
                self._offset_opcode(opcode, a_start, b_start)
                for opcode in diff.get_opcodes()
            ]

            updated_total_lines = acc.total_lines + num_lines_in_block
            updated_weighted_match_ratio = (
                acc.weighted_match_ratio + num_lines_in_block * diff.ratio()
            )

            return _IntermediateSequenceMatch(
                opcodes=updated_opcodes,
                total_lines=updated_total_lines,
                weighted_match_ratio=updated_weighted_match_ratio,
            )

        valid_pinned_lines = (
            (a_index, b_index)
            for a_index, b_index in pinned_lines
            if a_index in range(len(a)) and b_index in range(len(b))
        )

        # Add the first and last index to the pins so we can iterate over all sections with `pairwise()`
        pins_with_first_and_last = itertools.chain(
            [(0, 0)], valid_pinned_lines, [(len(a), len(b))]
        )

        result = functools.reduce(
            accumulator,
            pairwise(pins_with_first_and_last),
            _IntermediateSequenceMatch(),
        )
        self._ratio = (
            result.weighted_match_ratio / result.total_lines
            if result.total_lines > 0
            else 1.0
        )
        self._opcodes = result.opcodes

    @staticmethod
    def _offset_opcode(
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

    def get_opcodes(self) -> list[tuple[str, int, int, int, int]]:
        return self._opcodes

    def ratio(self):
        return self._ratio

    def get_grouped_opcodes(
        self, n=3
    ) -> Iterable[list[tuple[str, int, int, int, int]]]:
        """
        Taken from the Python 3.12 standard library, `difflib.py`, published under PSF license, GPL compatible.

        A more hacky approach would be to inherit from `SequenceMatcher` and reuse the implementation,
        but that would depend on the internal behaviour that `get_grouped_opcodes()` internally
        calls `get_opcodes()`.

        See `difflib.SequenceMatcher.get_grouped_opcodes()` for more details.
        """

        codes = self.get_opcodes()
        if not codes:
            codes = [("equal", 0, 1, 0, 1)]
        # Fixup leading and trailing groups if they show no changes.
        if codes[0][0] == "equal":
            tag, i1, i2, j1, j2 = codes[0]
            codes[0] = tag, max(i1, i2 - n), i2, max(j1, j2 - n), j2
        if codes[-1][0] == "equal":
            tag, i1, i2, j1, j2 = codes[-1]
            codes[-1] = tag, i1, min(i2, i1 + n), j1, min(j2, j1 + n)

        nn = n + n
        group = []
        for tag, i1, i2, j1, j2 in codes:
            # End the current group and start a new one whenever
            # there is a large range with no changes.
            if tag == "equal" and i2 - i1 > nn:
                group.append((tag, i1, min(i2, i1 + n), j1, min(j2, j1 + n)))
                yield group
                group = []
                i1, j1 = max(i1, i2 - n), max(j1, j2 - n)
            group.append((tag, i1, i2, j1, j2))
        if group and not (len(group) == 1 and group[0][0] == "equal"):
            yield group
