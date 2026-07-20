import logging
from typing import Sequence

from reccmp.compare.asm.effective import (
    JCC_MNEMONICS,
    LineEffects,
    effects_conflict,
    flags_dead_at,
    sequence_effects,
    verify_effective_match,
)
from reccmp.compare.asm.parse import AsmExcerpt
from reccmp.compare.pinned_sequences import DiffOpcode

logger = logging.getLogger(__name__)

# Alignment padding emitted between functions. int3 traps if executed, so
# it is only trimmed as trailing padding behind an instruction that does
# not fall through — never excused as a one-sided instruction.
_PADDING = ("nop", "int3")


def _trim_padding(asm: list[str]) -> list[str]:
    """Strip trailing nop/int3 alignment padding, but only behind an
    instruction that does not fall through into it."""
    end = len(asm)
    while end > 0 and asm[end - 1] in _PADDING:
        end -= 1
    if 0 < end < len(asm) and asm[end - 1].partition(" ")[0] in ("ret", "jmp"):
        return asm[:end]
    return asm


def find_effective_match(
    codes: Sequence[DiffOpcode],
    orig_asm: list[str],
    recomp_asm: list[str],
    orig_addrs: Sequence[int | None] | None = None,
) -> bool:
    """Check whether the two sequences of instructions are an effective match.
    Meaning: do they differ only by instruction order or register selection?

    The relational verifier (see effective.py) proves equivalence modulo
    register allocation, commutative-operand order and inverted compare/jump
    conditions. Instruction-scheduling differences are handled by undoing
    relocations that are proven independent of everything they cross, then
    running the verifier on the reordered sequence — so relocations compose
    with register renames and operand swaps.

    `orig_addrs` (optional) provides the virtual address of each orig line;
    with it, a relocation may cross a forward conditional jump whose target
    lies within the crossed region."""
    # Plain lockstep pairing first (with trailing alignment padding
    # trimmed): for equal-length sequences the diff's insert/delete blocks
    # can misalign lines that pair up fine positionally.
    trimmed_orig = _trim_padding(orig_asm)
    trimmed_recomp = _trim_padding(recomp_asm)
    if verify_effective_match(trimmed_orig, trimmed_recomp):
        if len(trimmed_orig) != len(orig_asm) or len(trimmed_recomp) != len(recomp_asm):
            logger.debug("effective match: lockstep (padding trimmed)")
        else:
            logger.debug("effective match: lockstep")
        return True

    # Diff-aligned pairing: handles length differences (one-sided entries
    # for whitelisted unobservable instructions, e.g. a redundant
    # register copy) and transposed independent lines.
    if verify_effective_match(orig_asm, recomp_asm, codes):
        logger.debug("effective match: diff-aligned")
        return True

    reordered = undo_relocations(codes, orig_asm, recomp_asm, orig_addrs)
    if reordered is not None and verify_effective_match(orig_asm, reordered):
        logger.debug("effective match: instruction relocation")
        return True

    return False


def undo_relocations(
    codes: Sequence[DiffOpcode],
    orig_asm: list[str],
    recomp_asm: list[str],
    orig_addrs: Sequence[int | None] | None = None,
) -> list[str] | None:
    """If every diff insertion can be paired with an equal-text deletion
    whose move is proven independent of all crossed instructions, return
    recomp_asm reordered into orig's instruction order. Returns None when
    the diffs are not (only) relocations."""
    # pylint: disable=too-many-return-statements
    if len(orig_asm) != len(recomp_asm):
        return None

    # Sorted for deterministic matching when several identical lines
    # could pair up. (GH #324)
    deletes = sorted(
        i for code, i1, i2, _, __ in codes for i in range(i1, i2) if code == "delete"
    )
    # `i1` is the index of the orig_asm list where this line will be inserted.
    # This is not necessarily equal to `j1`, the index of the inserted line in recomp_asm.
    # Therefore we need to save `i1` so that we verify each line between the start and end of the move. (GH #332)
    inserts = [
        (i1, j)
        for code, i1, __, j1, j2 in codes
        for j in range(j1, j2)
        if code == "insert"
    ]

    if not inserts or len(inserts) != len(deletes):
        return None

    effects = sequence_effects(orig_asm)
    if effects is None:
        return None

    addr_index: dict[int, int] | None = None
    if orig_addrs is not None:
        addr_index = {addr: k for k, addr in enumerate(orig_addrs) if addr is not None}

    pairs: dict[int, int] = {}
    remaining = list(deletes)
    for orig_dest, j in inserts:
        line = recomp_asm[j]
        matched = None
        for i in remaining:
            if orig_asm[i] != line:
                continue
            if _can_relocate(effects, orig_asm, i, orig_dest, orig_addrs, addr_index):
                matched = i
                break
        if matched is None:
            return None
        pairs[j] = matched
        remaining.remove(matched)

    # Sort recomp lines by their position in orig's coordinate system:
    # matching lines keep their diff-aligned position, relocated lines take
    # the position of their paired deletion.
    key: dict[int, int] = {}
    for code, i1, i2, j1, j2 in codes:
        if code in ("equal", "replace"):
            if (i2 - i1) != (j2 - j1):
                return None
            for i, j in zip(range(i1, i2), range(j1, j2)):
                key[j] = i
        elif code == "insert":
            for j in range(j1, j2):
                key[j] = pairs[j]

    if len(key) != len(recomp_asm):
        return None

    order = sorted(range(len(recomp_asm)), key=key.__getitem__)
    reordered = [recomp_asm[j] for j in order]
    return None if reordered == recomp_asm else reordered


def _can_relocate(  # pylint: disable=too-many-positional-arguments
    effects: list[LineEffects],
    orig_asm: list[str],
    i: int,
    orig_dest: int,
    orig_addrs: Sequence[int | None] | None,
    addr_index: dict[int, int] | None,
) -> bool:
    """May the instruction at orig index `i` move to position `orig_dest`?
    Only if it is independent of every instruction it crosses: no register
    or flag dependency, no possibly-aliasing memory access, no x87 stack
    interaction and no control-flow barrier in between. (GH #324)"""
    moved = effects[i]
    if moved.barrier:
        return False

    # To account for a move in either direction:
    # the deleted line can precede or follow the inserted line.
    reloc_start = min(i, orig_dest)
    reloc_end = max(i, orig_dest)

    crossed_flag_writer = False
    for k in range(reloc_start, reloc_end):
        if k == i:
            continue
        other = effects[k]
        if other.barrier:
            # Exception: a forward conditional jump whose target lies within
            # the crossed region. The moved instruction then executes on
            # both the taken and the fallthrough path in both placements
            # (and it must not touch the flags the jump reads).
            if not moved.writes_flags and _forward_jcc_within(
                orig_asm, k, reloc_end, orig_addrs, addr_index
            ):
                continue
            return False
        if effects_conflict(moved, other):
            return False
        if other.writes_flags:
            crossed_flag_writer = True

    # If both the moved instruction and a crossed instruction write the
    # flags, the move changes which value the flags hold at the end of the
    # region: the flags must be dead there.
    if moved.writes_flags and crossed_flag_writer:
        after = reloc_end + 1 if reloc_end == i else reloc_end
        if not flags_dead_at(effects, after):
            return False

    return True


def _forward_jcc_within(
    orig_asm: list[str],
    k: int,
    reloc_end: int,
    orig_addrs: Sequence[int | None] | None,
    addr_index: dict[int, int] | None,
) -> bool:
    """Is orig_asm[k] a forward conditional jump whose target is at or
    before index reloc_end? Requires instruction addresses to resolve the
    displacement."""
    if orig_addrs is None or addr_index is None or k + 1 >= len(orig_addrs):
        return False

    mnemonic, _, op_str = orig_asm[k].partition(" ")
    if mnemonic not in JCC_MNEMONICS:
        return False
    try:
        displacement = int(op_str, 16)
    except ValueError:
        return False
    if displacement <= 0:
        return False

    next_addr = orig_addrs[k + 1]
    if next_addr is None:
        return False

    target = addr_index.get(next_addr + displacement)
    return target is not None and k < target <= reloc_end


def assert_fixup(asm: AsmExcerpt):
    """Detect assert calls and replace the code filename and line number
    values with macros (from assert.h)."""
    for i, (_, line) in enumerate(asm):
        if "_assert" in line and line.startswith("call"):
            try:
                asm[i - 3] = (asm[i - 3][0], "push __LINE__")
                asm[i - 2] = (asm[i - 2][0], "push __FILE__")
            except IndexError:
                continue
