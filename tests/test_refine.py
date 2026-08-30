"""Tests for cross-side operand equivalence refinement.
Mismatching diff line pairs that differ only in structurally equivalent
address operands are turned into matches. See OperandRefiner."""

import pytest
from reccmp.difflib import DiffOpcode
from reccmp.compare.asm.parse import AsmExcerpt
from reccmp.compare.asm.refine import (
    ANCHOR_DELTA_LIMIT,
    OperandRefiner,
    _split_replace_block,
    instruction_skeleton,
)


def make_refiner(
    orig_candidates=None,
    recomp_candidates=None,
    orig_start=0x1000,
    recomp_start=0x5000,
    self_reach=0x100,
) -> OperandRefiner:
    empty: frozenset[tuple[int, int]] = frozenset()

    return OperandRefiner(
        orig_candidates=lambda addr: frozenset(
            (orig_candidates or {}).get(addr, empty)
        ),
        recomp_candidates=lambda addr: frozenset(
            (recomp_candidates or {}).get(addr, empty)
        ),
        orig_start=orig_start,
        recomp_start=recomp_start,
        self_reach=self_reach,
    )


####


def test_skeleton():
    """The skeleton is the instruction text with the address operands
    masked out. Instructions that differ only in address operands have
    the same skeleton."""
    a = instruction_skeleton(
        ("cmp eax, _array+8 (OFFSET)", ((0x2008, "_array+8 (OFFSET)", False),))
    )
    b = instruction_skeleton(
        ("cmp eax, _next (DATA)", ((0x3000, "_next (DATA)", False),))
    )
    assert a is not None
    assert a == b

    # Different structure = different skeleton
    c = instruction_skeleton(
        ("mov eax, _next (DATA)", ((0x3000, "_next (DATA)", False),))
    )
    assert a != c

    # Bogus record: replacement text does not appear in the line.
    assert (
        instruction_skeleton(("cmp eax, ebx", ((0x2008, "<OFFSET1>", False),))) is None
    )


def test_skeleton_multiple_operands():
    """Each operand is masked with its position so that shapes align."""
    rec = (
        "mov dword ptr [<OFFSET1>], <OFFSET2>",
        ((0x2000, "<OFFSET1>", False), (0x3000, "<OFFSET2>", False)),
    )
    skeleton = instruction_skeleton(rec)
    assert skeleton is not None
    assert "<OFFSET1>" not in skeleton and "<OFFSET2>" not in skeleton


def _refine_single(
    refiner: OperandRefiner,
    orig_line: tuple[int, str],
    recomp_line: tuple[int, str],
    orig_ops,
    recomp_ops,
    *,
    equal_lines=(),
):
    """Helper: run refine() on a diff with one mismatching line pair,
    plus optional equal lines that can provide anchors. Each equal line
    is (orig line addr, text, recomp line addr, orig op, recomp op)
    where the ops are the operand values behind the shared text.
    Returns the RefinedDiff or None."""
    orig: AsmExcerpt = [*[(line[0], line[1]) for line in equal_lines], orig_line]
    recomp: AsmExcerpt = [*[(line[2], line[1]) for line in equal_lines], recomp_line]
    n = len(equal_lines)
    opcodes: list[DiffOpcode] = []
    if n:
        opcodes.append(("equal", 0, n, 0, n))
    opcodes.append(("replace", n, n + 1, n, n + 1))

    orig_records = {orig_line[0]: (orig_line[1], tuple(orig_ops))}
    recomp_records = {recomp_line[0]: (recomp_line[1], tuple(recomp_ops))}
    for line_addr, text, line_addr2, op_value, op_value2 in equal_lines:
        # Anchor lines: same replacement text, one address operand each.
        orig_records[line_addr] = (text, ((op_value, text.split()[-1], False),))
        recomp_records[line_addr2] = (text, ((op_value2, text.split()[-1], False),))

    return refiner.refine(orig, recomp, opcodes, orig_records, recomp_records)


def test_refine_by_shared_candidate():
    """Both sides interpret their operand as the same matched entity at
    the same delta: the pair matches."""
    refiner = make_refiner(
        orig_candidates={0x2064: {(0x2000, 100), (0x2064, 0)}},
        recomp_candidates={0x6064: {(0x2000, 100)}},
    )

    result = _refine_single(
        refiner,
        (0x1010, "cmp eax, _next (DATA)"),
        (0x5010, "cmp eax, _table+100 (OFFSET)"),
        [(0x2064, "_next (DATA)", False)],
        [(0x6064, "_table+100 (OFFSET)", False)],
    )
    assert result is not None
    # The recomp line was rewritten to the orig text...
    assert result.recomp[-1] == (0x5010, "cmp eax, _next (DATA)")
    # ...and the pair is now scored as a match.
    assert ("equal", 0, 1, 0, 1) in result.opcodes


def test_refine_no_shared_candidate():
    """Different interpretations on each side: no match."""
    refiner = make_refiner(
        orig_candidates={0x2064: {(0x2064, 0)}},
        recomp_candidates={0x6064: {(0x2000, 100)}},
    )

    result = _refine_single(
        refiner,
        (0x1010, "cmp eax, _next (DATA)"),
        (0x5010, "cmp eax, _table+100 (OFFSET)"),
        [(0x2064, "_next (DATA)", False)],
        [(0x6064, "_table+100 (OFFSET)", False)],
    )
    assert result is None


def test_refine_by_function_interior():
    """References into the function's own body at the same relative
    offset (e.g. its own jump tables)."""
    refiner = make_refiner(orig_start=0x1000, recomp_start=0x5000, self_reach=0x100)

    result = _refine_single(
        refiner,
        (0x1010, "jmp dword ptr [ecx*4 + <OFFSET1>]"),
        (0x5010, "jmp dword ptr [ecx*4 + <OFFSET2>]"),
        [(0x1050, "<OFFSET1>", False)],
        [(0x5050, "<OFFSET2>", False)],
    )
    assert result is not None

    # Not within the function body in both images: no match.
    assert (
        _refine_single(
            refiner,
            (0x1010, "jmp dword ptr [ecx*4 + <OFFSET1>]"),
            (0x5010, "jmp dword ptr [ecx*4 + <OFFSET2>]"),
            [(0x1200, "<OFFSET1>", False)],
            [(0x5200, "<OFFSET2>", False)],
        )
        is None
    )


def test_refine_by_anchor():
    """References into an unannotated object can be equated if some other
    reference to the object was already matched up: both operands then
    show the same delta from the matching pair."""
    refiner = make_refiner()

    # The equal line pins (0x102000 <-> 0x106000) as the same object.
    # The mismatching operands are at delta 0x174 from that pair.
    result = _refine_single(
        refiner,
        (0x1010, "cmp eax, <OFFSET9>"),
        (0x5010, "cmp eax, <OFFSET7>"),
        [(0x102174, "<OFFSET9>", False)],
        [(0x106174, "<OFFSET7>", False)],
        equal_lines=[(0x2000, "mov eax, <OFFSET2>", 0x6000, 0x102000, 0x106000)],
    )
    assert result is not None

    # Different deltas: no match.
    assert (
        _refine_single(
            refiner,
            (0x1010, "cmp eax, <OFFSET9>"),
            (0x5010, "cmp eax, <OFFSET7>"),
            [(0x102174, "<OFFSET9>", False)],
            [(0x106170, "<OFFSET7>", False)],
            equal_lines=[(0x2000, "mov eax, <OFFSET2>", 0x6000, 0x102000, 0x106000)],
        )
        is None
    )


def test_refine_strict_operands():
    """A call target refers to the exact start of an entity. If a matched
    entity claims either address exactly, the other side must be the
    matched counterpart."""
    # orig 0x2000 <-> recomp 0x6000 is a matched function.
    # recomp 0x6005 is the start of another matched function whose orig
    # address is elsewhere.
    orig_candidates = {0x2000: {(0x2000, 0)}}
    recomp_candidates = {0x6000: {(0x2000, 0)}, 0x6005: {(0x2F00, 0)}}
    refiner = make_refiner(orig_candidates, recomp_candidates)

    # Same matched entity: ok. (would normally already match by name,
    # unless the entity has no name)
    result = _refine_single(
        refiner,
        (0x1010, "call <OFFSET1>"),
        (0x5010, "call <OFFSET2>"),
        [(0x2000, "<OFFSET1>", True)],
        [(0x6000, "<OFFSET2>", True)],
    )
    assert result is not None

    # 0x6005 is the start of a different matched entity, even though the
    # deltas from the anchor pair (provided by the equal line) agree.
    # A slack interpretation must never override an exact one.
    assert (
        _refine_single(
            refiner,
            (0x1010, "call <OFFSET5>"),
            (0x5010, "call Thunk of 'foo' (THUNK)"),
            [(0x2005, "<OFFSET5>", True)],
            [(0x6005, "Thunk of 'foo' (THUNK)", True)],
            equal_lines=[(0x2000, "call <OFFSET2>", 0x6000, 0x2000, 0x6000)],
        )
        is None
    )


def test_refine_strict_unannotated_by_anchor():
    """A call to a function that no annotation covers (e.g. a static
    function that is invisible in the PDB) can still be equated by its
    position relative to an anchor pair."""
    refiner = make_refiner()

    result = _refine_single(
        refiner,
        (0x1010, "call _write_multi_char (FUNCTION)"),
        (0x5010, "call <OFFSET3>"),
        [(0x2300, "_write_multi_char (FUNCTION)", True)],
        [(0x6300, "<OFFSET3>", True)],
        equal_lines=[(0x2000, "call _write_char (FUNCTION)", 0x6000, 0x2000, 0x6000)],
    )
    assert result is not None


def test_refine_different_shape():
    """Lines with different instruction structure never match."""
    refiner = make_refiner(
        orig_candidates={0x2064: {(0x2000, 100)}},
        recomp_candidates={0x6064: {(0x2000, 100)}},
    )

    result = _refine_single(
        refiner,
        (0x1010, "cmp eax, _next (DATA)"),
        (0x5010, "mov eax, _table+100 (OFFSET)"),
        [(0x2064, "_next (DATA)", False)],
        [(0x6064, "_table+100 (OFFSET)", False)],
    )
    assert result is None


def test_refine_stale_record():
    """If the line text changed after sanitization (e.g. assert_fixup),
    the operand record no longer applies: no match."""
    refiner = make_refiner(
        orig_candidates={0x2064: {(0x2000, 100)}},
        recomp_candidates={0x6064: {(0x2000, 100)}},
    )

    orig: AsmExcerpt = [(0x1010, "cmp eax, _next (DATA) MODIFIED")]
    recomp: AsmExcerpt = [(0x5010, "cmp eax, _table+100 (OFFSET)")]
    opcodes: list[DiffOpcode] = [("replace", 0, 1, 0, 1)]
    orig_records = {
        0x1010: ("cmp eax, _next (DATA)", ((0x2064, "_next (DATA)", False),))
    }
    recomp_records = {
        0x5010: (
            "cmp eax, _table+100 (OFFSET)",
            ((0x6064, "_table+100 (OFFSET)", False),),
        )
    }

    assert refiner.refine(orig, recomp, opcodes, orig_records, recomp_records) is None


def test_refine_patches_locally():
    """The diff opcodes are patched in place: refined pairs become equal,
    everything else keeps its position. A replace block is split as
    needed and leftover lines stay mismatched."""
    refiner = make_refiner(
        orig_candidates={0x2064: {(0x2000, 100)}},
        recomp_candidates={0x6064: {(0x2000, 100)}},
    )

    orig: AsmExcerpt = [
        (0x1000, "push ebx"),
        (0x1001, "cmp eax, _next (DATA)"),
        (0x1007, "xor eax, eax"),
        (0x1009, "ret"),
    ]
    recomp: AsmExcerpt = [
        (0x5000, "push ebx"),
        (0x5001, "cmp eax, _table+100 (OFFSET)"),
        (0x5007, "sub eax, eax"),
    ]
    opcodes: list[DiffOpcode] = [
        ("equal", 0, 1, 0, 1),
        ("replace", 1, 4, 1, 3),
    ]
    orig_records = {
        0x1001: ("cmp eax, _next (DATA)", ((0x2064, "_next (DATA)", False),))
    }
    recomp_records = {
        0x5001: (
            "cmp eax, _table+100 (OFFSET)",
            ((0x6064, "_table+100 (OFFSET)", False),),
        )
    }

    result = refiner.refine(orig, recomp, opcodes, orig_records, recomp_records)
    assert result is not None
    assert result.recomp[1] == (0x5001, "cmp eax, _next (DATA)")
    # The refined pair joins the preceding equal block; the rest of the
    # replace block (including the leftover orig line) stays.
    assert result.opcodes == [
        ("equal", 0, 2, 0, 2),
        ("replace", 2, 4, 2, 3),
    ]


@pytest.mark.parametrize(
    "refined,expected",
    (
        # Trailing unrefined run absorbs the leftover lines.
        (
            [True, False],
            [("equal", 10, 11, 20, 21), ("replace", 11, 14, 21, 22)],
        ),
        # Trailing refined run: leftover orig lines are a deletion.
        (
            [False, True],
            [
                ("replace", 10, 11, 20, 21),
                ("equal", 11, 12, 21, 22),
                ("delete", 12, 14, 22, 22),
            ],
        ),
    ),
)
def test_split_replace_block(refined, expected):
    # pylint: disable=protected-access
    assert _split_replace_block(("replace", 10, 14, 20, 22), refined) == expected


def test_refine_conflicting_exact_candidates():
    """Both operands sit exactly on different matched entities: an
    agreeing anchor may not override the annotations."""
    refiner = make_refiner(
        orig_candidates={0x102174: {(0x102174, 0)}},
        recomp_candidates={0x106174: {(0x2F00, 0)}},
    )

    result = _refine_single(
        refiner,
        (0x1010, "cmp eax, _alpha (DATA)"),
        (0x5010, "cmp eax, _beta (DATA)"),
        [(0x102174, "_alpha (DATA)", False)],
        [(0x106174, "_beta (DATA)", False)],
        equal_lines=[(0x2000, "mov eax, <OFFSET2>", 0x6000, 0x102000, 0x106000)],
    )
    assert result is None


def test_refine_anchor_delta_boundary():
    """The anchor rule accepts a delta of exactly ANCHOR_DELTA_LIMIT and
    rejects one byte more."""
    refiner = make_refiner()

    at_limit = _refine_single(
        refiner,
        (0x1010, "cmp eax, <OFFSET9>"),
        (0x5010, "cmp eax, <OFFSET7>"),
        [(0x102000 + ANCHOR_DELTA_LIMIT, "<OFFSET9>", False)],
        [(0x106000 + ANCHOR_DELTA_LIMIT, "<OFFSET7>", False)],
        equal_lines=[(0x2000, "mov eax, <OFFSET2>", 0x6000, 0x102000, 0x106000)],
    )
    assert at_limit is not None

    past_limit = _refine_single(
        refiner,
        (0x1010, "cmp eax, <OFFSET9>"),
        (0x5010, "cmp eax, <OFFSET7>"),
        [(0x102001 + ANCHOR_DELTA_LIMIT, "<OFFSET9>", False)],
        [(0x106001 + ANCHOR_DELTA_LIMIT, "<OFFSET7>", False)],
        equal_lines=[(0x2000, "mov eax, <OFFSET2>", 0x6000, 0x102000, 0x106000)],
    )
    assert past_limit is None


def test_refine_self_reach_boundary():
    """A reference into the function's own body must be strictly interior."""
    refiner = make_refiner(orig_start=0x1000, recomp_start=0x5000, self_reach=0x100)

    interior = _refine_single(
        refiner,
        (0x1010, "cmp eax, <OFFSET9>"),
        (0x5010, "cmp eax, <OFFSET7>"),
        [(0x10FF, "<OFFSET9>", False)],
        [(0x50FF, "<OFFSET7>", False)],
    )
    assert interior is not None

    past_end = _refine_single(
        refiner,
        (0x1010, "cmp eax, <OFFSET9>"),
        (0x5010, "cmp eax, <OFFSET7>"),
        [(0x1100, "<OFFSET9>", False)],
        [(0x5100, "<OFFSET7>", False)],
    )
    assert past_end is None
