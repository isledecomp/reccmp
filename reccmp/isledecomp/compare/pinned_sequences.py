from difflib import SequenceMatcher
from itertools import pairwise
import itertools
from typing import Iterable, Sequence


DiffOpcode = tuple[str, int, int, int, int]


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
        valid_pinned_lines = (
            (a_index, b_index)
            for a_index, b_index in pinned_lines
            if a_index in range(len(a)) and b_index in range(len(b))
        )

        # Add the first and last index to the pins so we can iterate over all sections with `pairwise()`
        pins_with_first_and_last = itertools.chain(
            [(0, 0)], valid_pinned_lines, [(len(a), len(b))]
        )

        all_opcodes = []
        total_lines = 0
        weighted_match_ratio = 0.0

        for (a_start, b_start), (a_end, b_end) in pairwise(pins_with_first_and_last):
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
            all_opcodes += [
                self._offset_opcode(opcode, a_start, b_start)
                for opcode in diff.get_opcodes()
            ]

            total_lines += num_lines_in_block
            weighted_match_ratio += num_lines_in_block * diff.ratio()

        self._ratio = weighted_match_ratio / total_lines if total_lines > 0 else 1.0
        self._opcodes = all_opcodes

    @staticmethod
    def _offset_opcode(
        group: DiffOpcode, offset_orig: int, offset_recomp: int
    ) -> DiffOpcode:
        op, orig_start, orig_end, recomp_start, recomp_end = group
        return (
            op,
            orig_start + offset_orig,
            orig_end + offset_orig,
            recomp_start + offset_recomp,
            recomp_end + offset_recomp,
        )

    def get_opcodes(self) -> list[DiffOpcode]:
        return self._opcodes

    def ratio(self):
        return self._ratio

    def get_grouped_opcodes(self, n=3) -> Iterable[list[DiffOpcode]]:
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
