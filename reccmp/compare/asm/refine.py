"""Cross-side operand equivalence.

The orig and recomp assembly are sanitized independently: each address
operand is replaced by the name of the entity it resolves to, or by a
numbered placeholder. Two operands therefore only compare equal if both
sides produce the same text. This misses operands that are displaced but
structurally identical: they point at the same matched entity with the
same delta, but at least one side cannot produce a (or produces a
different) name for its address. For example:

- A reference one-past-the-end of an array that coincides with the start
  of the next variable in one image but not in the other.
- A reference into the function's own body (e.g. its jump tables) which
  moved because the function linked at a different address.
- A walking pointer bound like `array + sizeof(array) + field_offset`.

This module re-examines the mismatching line pairs of the initial diff.
If two lines differ only in address operands, and every such operand pair
shares an interpretation -- the same matched entity at the same delta, or
the same delta from a pair of operands that already compare equal -- then
the pair is turned into a match: the recomp line is rewritten to the orig
text and the diff opcodes are patched in place.

Two properties keep this safe:

- Equivalence is strictly symmetric. BOTH sides must yield the same
  interpretation under the same rule. A one-sided fuzzy resolution (e.g.
  "this is probably entity X plus some slack") is never accepted, because
  it would override the exact resolution on the other side.
- The diff is patched locally: a refined pair becomes an equal pair, and
  nothing else moves. The match ratio can only increase, and the diff is
  never re-run on the rewritten text (which could pair the rewritten
  lines with unrelated lines elsewhere in the function).
"""

from dataclasses import dataclass
from typing import Mapping, Sequence

from reccmp.difflib import DiffOpcode
from .parse import AsmExcerpt, OpRecord
from .replacement import CandidateLookupProtocol

# Upper bound for the displacement from an anchor operand pair.
# (i.e. operands equated by the same delta from an already-matching
# operand pair rather than by an annotated entity)
ANCHOR_DELTA_LIMIT = 0x1000

_SENTINEL = "\x00"


def instruction_skeleton(record: OpRecord) -> str | None:
    """Mask out each address operand from the instruction text.
    Two instructions that differ only in address operands have the same
    skeleton. Returns None if some replacement text cannot be located in
    the instruction text. (This should not happen, but if it does, the
    instruction is not usable for operand comparison.)"""
    text, ops = record
    for i, (_, op_text, _) in enumerate(ops):
        index = text.find(op_text)
        if index == -1:
            return None

        text = f"{text[:index]}{_SENTINEL}{i}{_SENTINEL}{text[index + len(op_text) :]}"

    return text


def _merge_opcodes(codes: list[DiffOpcode]) -> list[DiffOpcode]:
    """Merge adjacent opcodes with the same tag."""
    merged: list[DiffOpcode] = []
    for code in codes:
        if merged and merged[-1][0] == code[0]:
            tag, i1, _, j1, _ = merged[-1]
            merged[-1] = (tag, i1, code[2], j1, code[4])
        else:
            merged.append(code)

    return merged


@dataclass(frozen=True)
class RefinedDiff:
    recomp: AsmExcerpt
    opcodes: list[DiffOpcode]


@dataclass(frozen=True)
class OperandRefiner:
    """Turns mismatching diff line pairs whose address operands are
    structurally equivalent into matches. See the module docstring."""

    orig_candidates: CandidateLookupProtocol
    recomp_candidates: CandidateLookupProtocol
    # Function under comparison: start address in each image and the
    # number of bytes that are certainly interior to the function in
    # both images.
    orig_start: int
    recomp_start: int
    self_reach: int

    def refine(
        self,
        orig: AsmExcerpt,
        recomp: AsmExcerpt,
        opcodes: Sequence[DiffOpcode],
        orig_records: Mapping[int, OpRecord],
        recomp_records: Mapping[int, OpRecord],
    ) -> RefinedDiff | None:
        """Detect structurally equivalent line pairs among the 'replace'
        blocks of the diff. Each equivalent pair is scored as a match:
        the recomp line text is rewritten to the orig text and the diff
        opcodes are patched accordingly. Returns None if no line pair
        was refined."""
        anchors = self._harvest_anchors(
            orig, recomp, opcodes, orig_records, recomp_records
        )

        new_recomp: AsmExcerpt | None = None
        new_opcodes: list[DiffOpcode] = []

        for code in opcodes:
            tag, i1, i2, j1, j2 = code
            if tag != "replace":
                new_opcodes.append(code)
                continue

            # If the block sizes differ, compare the leading pairs.
            refined = [
                self._equivalent_lines(
                    orig[i1 + k], recomp[j1 + k], orig_records, recomp_records, anchors
                )
                for k in range(min(i2 - i1, j2 - j1))
            ]
            if not any(refined):
                new_opcodes.append(code)
                continue

            if new_recomp is None:
                new_recomp = list(recomp)

            for k, is_refined in enumerate(refined):
                if is_refined:
                    new_recomp[j1 + k] = (recomp[j1 + k][0], orig[i1 + k][1])

            new_opcodes.extend(_split_replace_block(code, refined))

        if new_recomp is None:
            return None

        return RefinedDiff(recomp=new_recomp, opcodes=_merge_opcodes(new_opcodes))

    def _get_op_records(
        self,
        orig_line: tuple[int | None, str],
        recomp_line: tuple[int | None, str],
        orig_records: Mapping[int, OpRecord],
        recomp_records: Mapping[int, OpRecord],
    ) -> tuple[OpRecord, OpRecord] | None:
        """Operand records for the given line pair, or None if either line
        has no address operands or was modified after sanitization.
        (e.g. by assert_fixup)"""
        orig_addr, orig_text = orig_line
        recomp_addr, recomp_text = recomp_line
        if orig_addr is None or recomp_addr is None:
            return None

        orig_record = orig_records.get(orig_addr)
        recomp_record = recomp_records.get(recomp_addr)
        if orig_record is None or recomp_record is None:
            return None

        if orig_record[0] != orig_text or recomp_record[0] != recomp_text:
            return None

        return (orig_record, recomp_record)

    def _harvest_anchors(
        self,
        orig: AsmExcerpt,
        recomp: AsmExcerpt,
        opcodes: Sequence[DiffOpcode],
        orig_records: Mapping[int, OpRecord],
        recomp_records: Mapping[int, OpRecord],
    ) -> list[tuple[int, int]]:
        """Address operand pairs (orig addr, recomp addr) that the diff has
        already matched up: both operands got the same replacement text on
        a line that compares equal. Such a pair pins down the location of
        the same object in both images -- even an object we know nothing
        else about, when the operands are matching placeholders -- and can
        then anchor references displaced from it."""
        anchors: set[tuple[int, int]] = set()

        for tag, i1, i2, j1, j2 in opcodes:
            if tag != "equal":
                continue

            for i, j in zip(range(i1, i2), range(j1, j2)):
                records = self._get_op_records(
                    orig[i], recomp[j], orig_records, recomp_records
                )
                if records is None:
                    continue

                orig_ops, recomp_ops = records[0][1], records[1][1]
                if len(orig_ops) != len(recomp_ops):
                    continue

                for (orig_value, orig_op, _), (recomp_value, recomp_op, _) in zip(
                    orig_ops, recomp_ops
                ):
                    # A raw hex operand does not pair up two addresses;
                    # the values are simply identical.
                    if orig_op == recomp_op and not orig_op.startswith("0x"):
                        anchors.add((orig_value, recomp_value))

        return sorted(anchors)

    def _equivalent_lines(
        self,
        orig_line: tuple[int | None, str],
        recomp_line: tuple[int | None, str],
        orig_records: Mapping[int, OpRecord],
        recomp_records: Mapping[int, OpRecord],
        anchors: Sequence[tuple[int, int]],
    ) -> bool:
        """Do these mismatching lines differ only in address operands that
        are structurally equivalent?"""
        records = self._get_op_records(
            orig_line, recomp_line, orig_records, recomp_records
        )
        if records is None:
            return False

        orig_record, recomp_record = records
        orig_ops, recomp_ops = orig_record[1], recomp_record[1]
        if not orig_ops or len(orig_ops) != len(recomp_ops):
            return False

        skeleton = instruction_skeleton(orig_record)
        if skeleton is None or skeleton != instruction_skeleton(recomp_record):
            return False

        return all(
            self._equivalent_operands(orig_op, recomp_op, anchors)
            for orig_op, recomp_op in zip(orig_ops, recomp_ops)
        )

    def _equivalent_operands(
        self,
        orig_op: tuple[int, str, bool],
        recomp_op: tuple[int, str, bool],
        anchors: Sequence[tuple[int, int]],
    ) -> bool:
        orig_value, orig_text, orig_strict = orig_op
        recomp_value, recomp_text, recomp_strict = recomp_op

        if orig_text == recomp_text:
            # This operand did not cause the mismatch.
            return True

        orig_cands = self.orig_candidates(orig_value)
        recomp_cands = self.recomp_candidates(recomp_value)

        if orig_strict or recomp_strict:
            # A call target or indirect pointer slot refers to the exact
            # start of an entity, so only the delta=0 interpretation
            # counts.
            if (orig_value, 0) in recomp_cands:
                # The same matched entity on both sides.
                return True

            # If a matched entity claims either address exactly, but is
            # not matched with the other address, then the operands refer
            # to two different things.
            if any(delta == 0 for _, delta in orig_cands) or any(
                delta == 0 for _, delta in recomp_cands
            ):
                return False

            # Otherwise: no annotation covers this operand (e.g. a call
            # to a static function that is invisible in the PDB), and it
            # may still be equated by the position-based rules below.
        elif orig_cands & recomp_cands:
            # Same matched entity at the same delta.
            return True

        # Reference into the body of the function under comparison?
        # (e.g. its own jump tables)
        delta = orig_value - self.orig_start
        if delta == recomp_value - self.recomp_start and 0 <= delta < self.self_reach:
            return True

        # Same delta from an anchor pair? This can equate references into
        # objects that are not annotated at all, if some other reference
        # to the object has already been matched up.
        return any(
            orig_value - orig_anchor == recomp_value - recomp_anchor
            and abs(orig_value - orig_anchor) <= ANCHOR_DELTA_LIMIT
            for orig_anchor, recomp_anchor in anchors
        )


def _split_replace_block(code: DiffOpcode, refined: Sequence[bool]) -> list[DiffOpcode]:
    """Split a 'replace' opcode into alternating 'equal' (refined pairs)
    and 'replace' segments. Any leftover lines (if the block sides have
    different lengths) stay mismatched."""
    _, i1, i2, j1, j2 = code
    length = len(refined)
    result: list[DiffOpcode] = []

    start = 0
    while start < length:
        end = start
        while end < length and refined[end] == refined[start]:
            end += 1

        if refined[start]:
            result.append(("equal", i1 + start, i1 + end, j1 + start, j1 + end))
        elif end == length:
            # Attach the leftover lines to the final mismatching segment.
            result.append(("replace", i1 + start, i2, j1 + start, j2))
            return result

        else:
            result.append(("replace", i1 + start, i1 + end, j1 + start, j1 + end))

        start = end

    # The final segment was refined. Emit the leftover lines separately.
    if i1 + length < i2:
        result.append(("delete", i1 + length, i2, j2, j2))
    elif j1 + length < j2:
        result.append(("insert", i2, i2, j1 + length, j2))

    return result
