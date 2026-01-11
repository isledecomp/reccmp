import dataclasses
from typing import Iterable, Sequence
from typing_extensions import NotRequired, TypedDict

from reccmp.isledecomp.compare.pinned_sequences import DiffOpcode
from reccmp.isledecomp.difflib import get_grouped_opcodes
from reccmp.isledecomp.types import EntityType

CombinedDiffInput = list[tuple[str, str]]


@dataclasses.dataclass
class FunctionCompareResult:
    codes: list[DiffOpcode] = dataclasses.field(default_factory=list)
    orig_inst: CombinedDiffInput = dataclasses.field(default_factory=list)
    recomp_inst: CombinedDiffInput = dataclasses.field(default_factory=list)
    is_effective_match: bool = False
    match_ratio: float = 0.0


class MatchingOrMismatchingBlock(TypedDict):
    # I tried a union and narrowing, but this does not work in mypy - see https://github.com/python/mypy/issues/11080
    both: NotRequired[list[tuple[str, str, str]]]
    orig: NotRequired[list[tuple[str, str]]]
    recomp: NotRequired[list[tuple[str, str]]]


# tuple[str, list[...]]: One contiguous part of the diff (without skipping matching code)
# list[...]: The list of all the contiguous diffs of a given function
CombinedDiffOutput = list[tuple[str, list[MatchingOrMismatchingBlock]]]


def combined_diff(
    grouped_opcodes: Iterable[Sequence[DiffOpcode]],
    orig_combined: CombinedDiffInput,
    recomp_combined: CombinedDiffInput,
) -> CombinedDiffOutput:
    """We want to diff the original and recomp assembly. The "combined" assembly
    input has two components: the address of the instruction and the assembly text.
    We have already diffed the text only. This is the SequenceMatcher object.
    The SequenceMatcher can generate "opcodes" that describe how to turn "Text A"
    into "Text B". These refer to list indices of the original arrays, so we can
    use those to create the final diff and include the address for each line of assembly.
    This is almost the same procedure as the difflib.unified_diff function, but we
    are reusing the already generated SequenceMatcher object.
    """

    unified_diff = []

    for group in grouped_opcodes:
        subgroups: list[MatchingOrMismatchingBlock] = []

        # Keep track of the addresses we've seen in this diff group.
        # This helps create the "@@" line. (Does this have a name?)
        # Do it this way because not every line in each list will have an
        # address. If our context begins or ends on a line that does not
        # have one, we will have an incomplete range string.
        orig_addrs = set()
        recomp_addrs = set()

        first, last = group[0], group[-1]
        orig_range = len(orig_combined[first[1] : last[2]])
        recomp_range = len(recomp_combined[first[3] : last[4]])

        for code, i1, i2, j1, j2 in group:
            if code == "equal":
                # The sections are equal, so the list slices are guaranteed
                # to have the same length. We only need the diffed value (asm text)
                # from one of the lists, but we need the addresses from both.
                # Use zip to put the two lists together and then take out what we want.
                both = [
                    # Prefer recomp over orig instruction because it may have more information (e.g. source code line)
                    (orig_addr, recomp_instr, recomp_addr)
                    for ((orig_addr, _), (recomp_addr, recomp_instr)) in zip(
                        orig_combined[i1:i2], recomp_combined[j1:j2]
                    )
                ]

                for orig_addr, _, recomp_addr in both:
                    if orig_addr is not None:
                        orig_addrs.add(orig_addr)

                    if recomp_addr is not None:
                        recomp_addrs.add(recomp_addr)

                subgroups.append({"both": both})
            else:
                for orig_addr, _ in orig_combined[i1:i2]:
                    if orig_addr is not None:
                        orig_addrs.add(orig_addr)

                for recomp_addr, _ in recomp_combined[j1:j2]:
                    if recomp_addr is not None:
                        recomp_addrs.add(recomp_addr)

                subgroups.append(
                    {
                        "orig": orig_combined[i1:i2],
                        "recomp": recomp_combined[j1:j2],
                    }
                )

        orig_sorted = sorted(orig_addrs)
        recomp_sorted = sorted(recomp_addrs)

        # We could get a diff group that has no original addresses.
        # This might happen for a stub function where we are not able to
        # produce even a single instruction from the original.
        # In that case, show the best slug line that we can.
        def peek_front(list_, default=""):
            try:
                return list_[0]
            except IndexError:
                return default

        orig_first = peek_front(orig_sorted)
        recomp_first = peek_front(recomp_sorted)

        diff_slug = f"@@ -{orig_first},{orig_range} +{recomp_first},{recomp_range} @@"

        unified_diff.append((diff_slug, subgroups))

    return unified_diff


def compare_result_to_udiff(
    result: FunctionCompareResult, *, grouped: bool = True
) -> CombinedDiffOutput:
    if grouped:
        opcode_groups = list(get_grouped_opcodes(result.codes, n=10))
    else:
        # One group.
        opcode_groups = [result.codes]

    return combined_diff(opcode_groups, result.orig_inst, result.recomp_inst)


@dataclasses.dataclass
class DiffReport:
    match_type: EntityType
    orig_addr: int
    recomp_addr: int
    name: str
    result: FunctionCompareResult = dataclasses.field(
        default_factory=FunctionCompareResult
    )
    is_stub: bool = False
    is_library: bool = False

    @property
    def ratio(self) -> float:
        return self.result.match_ratio

    @property
    def is_effective_match(self) -> bool:
        return self.result.is_effective_match

    @property
    def effective_ratio(self) -> float:
        return 1.0 if self.is_effective_match else self.ratio

    def __str__(self) -> str:
        """For debug purposes. Proper diff printing (with coloring) is in another module."""
        return f"{self.name} (0x{self.orig_addr:x}) {self.ratio*100:.02f}%{'*' if self.is_effective_match else ''}"
