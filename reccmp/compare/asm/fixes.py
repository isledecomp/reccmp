import re
from typing import Sequence

from reccmp.compare.asm.effective import (
    effects_conflict,
    flags_dead_at,
    line_effects,
    verify_effective_match,
)
from reccmp.compare.asm.parse import AsmExcerpt
from reccmp.compare.pinned_sequences import DiffOpcode

ALLOWED_JUMP_SWAPS = (
    ("ja", "jb"),
    ("jae", "jbe"),
    ("jb", "ja"),
    ("jbe", "jae"),
    ("jg", "jl"),
    ("jge", "jle"),
    ("jl", "jg"),
    ("jle", "jge"),
    ("je", "je"),
    ("jne", "jne"),
)


def jump_swap_ok(a: str, b: str, cmp_instruction: str = "cmp") -> bool:
    """For the instructions a,b, are they both jump instructions
    that are compatible with a swapped cmp operand order?
    `test` is commutative: swapping its operands does not change the flags,
    so only an identical jump is compatible (jg/jl would change behavior)."""
    # Grab the mnemonic
    jmp_a, _, __ = a.partition(" ")
    jmp_b, _, __ = b.partition(" ")

    if cmp_instruction == "test":
        return jmp_a == jmp_b and jmp_a.startswith("j")

    return (jmp_a, jmp_b) in ALLOWED_JUMP_SWAPS


def _mnemonic(inst: str) -> str:
    if not inst:
        return ""
    return inst.split(" ", 1)[0].lower()


def _split_operands(inst: str) -> list[str]:
    _, _, operand_str = inst.partition(" ")
    if not operand_str:
        return []
    return [operand.strip() for operand in operand_str.split(",") if operand.strip()]


def is_operand_swap(a: str, b: str) -> bool:
    """This is a hack to avoid parsing the operands. It's not as simple as
    breaking on the comma because templates or string literals interfere
    with this. Instead we check:
        1. Do both strings use the exact same set of characters?
        2. If we do break on ', ', is the first token of each different?
    2 is needed to catch an edge case like:
        cmp eax, dword ptr [ecx + 0x1234]
        cmp ecx, dword ptr [eax + 0x1234]
    """
    return a.partition(", ")[0] != b.partition(", ")[0] and sorted(a) == sorted(b)


def get_patched_jump(a: str, b: str) -> str:
    """For jump instructions a, b, return `(mnemonic_a) (operand_b)`.
    The reason to do it this way (instead of just returning `a`) is that
    the jump instructions might use different displacement offsets
    or labels. If we just replace `b` with `a`, this diff would be
    incorrectly eliminated."""
    mnemonic_a, _, __ = a.partition(" ")
    _, __, operand_b = b.partition(" ")

    return mnemonic_a + " " + operand_b


def patch_mov_cmp_jmp(orig: list[str], recomp: list[str]) -> set[int]:
    return patch_mov_compare_jmp(orig, recomp, "cmp")


def patch_mov_test_jmp(orig: list[str], recomp: list[str]) -> set[int]:
    return patch_mov_compare_jmp(orig, recomp, "test")


def patch_mov_compare_jmp(
    orig: list[str], recomp: list[str], cmp_instruction: str
) -> set[int]:
    """Can we resolve the diffs between orig and recomp by patching
    swapped cmp instructions?
    For example:
        mov eax, dword ptr [ebp - 0x4]  mov eax, dword ptr [ebp - 0x8]
        cmp dword ptr [ebp - 0x8]       cmp dword ptr [ebp - 0x4]
        ja .label                       jb .label

    Returns set of fixed lines
    """

    # find the first "cmp"/"test" instruction
    cmp_index = next(
        (i for i, s in enumerate(orig) if s.startswith(cmp_instruction)), -1
    )

    # return if not found, or only found on first or last line
    # pylint: disable=too-many-boolean-expressions
    if (
        cmp_index in (-1, 0, len(orig) - 1)
        or cmp_index >= len(recomp) - 1
        or
        # recomp should also have a cmp in the same line
        not recomp[cmp_index].startswith(cmp_instruction)
        or
        # line before cmp must be a mov
        not orig[cmp_index - 1].startswith("mov")
        or not recomp[cmp_index - 1].startswith("mov")
        or
        # if the last lines are not a compatible jump difference
        not jump_swap_ok(orig[cmp_index + 1], recomp[cmp_index + 1], cmp_instruction)
    ):
        return set()

    # Checking if the combination of mov + cmp include the same set of characters
    # - that is, the set of operands are the same although switched in order
    if sorted(orig[cmp_index - 1] + orig[cmp_index]) == sorted(
        recomp[cmp_index - 1] + recomp[cmp_index]
    ):
        # We only register the fix if the jmp actually matches
        if orig[cmp_index + 1] == get_patched_jump(
            orig[cmp_index + 1], recomp[cmp_index + 1]
        ):
            return {0, 1, 2}
    return set()


def patch_mov_commutative(orig: list[str], recomp: list[str]) -> set[int]:
    """Can we resolve the diffs between orig and recomp by patching
        swapped operands in mov + commutative ops (add, and, or, xor, imul).
    For example:
        mov eax, dword ptr [ebp - 0x4]      mov eax, dword ptr [ebp - 0x8]
        add eax, dword ptr [ebp - 0x8]      add eax, dword ptr [ebp - 0x4]

    Returns set of fixed lines
    """

    valid_mnemonics = ("add", "and", "or", "xor", "imul")
    inst_index = next(
        (i for i, s in enumerate(orig) if _mnemonic(s) in valid_mnemonics), -1
    )

    # commutative op must exist and have a preceding line in both slices
    if inst_index in (-1, 0) or inst_index >= len(recomp):
        return set()

    # this pattern only handles mov + {valid_mnemonics}
    if (
        _mnemonic(recomp[inst_index]) != _mnemonic(orig[inst_index])
        or _mnemonic(orig[inst_index - 1]) != "mov"
        or _mnemonic(recomp[inst_index - 1]) != "mov"
    ):
        return set()

    orig_mov_ops = _split_operands(orig[inst_index - 1])
    recomp_mov_ops = _split_operands(recomp[inst_index - 1])
    orig_ops = _split_operands(orig[inst_index])
    recomp_ops = _split_operands(recomp[inst_index])

    # We expect these instructions to all have two operands.
    if any(
        len(operands) != 2
        for operands in (orig_mov_ops, recomp_mov_ops, orig_ops, recomp_ops)
    ):
        return set()

    # MOV destination must be the same register in both versions.
    mov_dest_norm = orig_mov_ops[0].lower()
    if mov_dest_norm != recomp_mov_ops[0].lower() or mov_dest_norm not in REGISTER_SET:
        return set()

    # Must target the same register and swap sources exactly.
    op_layout_ok = (
        len(orig_ops) == 2
        and len(recomp_ops) == 2
        and orig_ops[0].lower() == mov_dest_norm
        and recomp_ops[0].lower() == mov_dest_norm
    )
    swap_ok = orig_ops[1] == recomp_mov_ops[1] and recomp_ops[1] == orig_mov_ops[1]

    if op_layout_ok and swap_ok:
        return {inst_index - 1, inst_index}

    return set()


def patch_cmp_jmp(orig: list[str], recomp: list[str]) -> set[int]:
    return patch_compare_jmp(orig, recomp, "cmp")


def patch_test_jmp(orig: list[str], recomp: list[str]) -> set[int]:
    return patch_compare_jmp(orig, recomp, "test")


def patch_compare_jmp(
    orig: list[str], recomp: list[str], cmp_instruction: str
) -> set[int]:
    """Can we resolve the diffs between orig and recomp by patching
    swapped cmp instructions?
    For example:
        cmp eax, ebx                    cmp ebx, eax
        je .label                       je .label

        cmp eax, ebx                    cmp ebx, eax
        ja .label                       jb .label

    Returns set of fixed lines
    """

    # find the first "cmp"/"test" instruction
    cmp_index = next(
        (i for i, s in enumerate(orig) if s.startswith(cmp_instruction)), -1
    )
    # return if not found, or only found on the last line
    if (
        cmp_index in (-1, len(orig) - 1)
        or cmp_index >= len(recomp) - 1
        or
        # recomp should also have a cmp in the same line
        not recomp[cmp_index].startswith(cmp_instruction)
        or
        # if the last lines are not a compatible jump difference
        not jump_swap_ok(orig[cmp_index + 1], recomp[cmp_index + 1], cmp_instruction)
    ):
        return set()

    # Checking two things:
    # Are the cmp operands flipped?
    # Is the jump instruction compatible with a flip?
    if is_operand_swap(orig[cmp_index], recomp[cmp_index]):
        if orig[cmp_index + 1] == get_patched_jump(
            orig[cmp_index + 1], recomp[cmp_index + 1]
        ):
            return {cmp_index, cmp_index + 1}
    return set()


def patch_fld_fmul(orig: list[str], recomp: list[str]) -> set[int]:
    """Can we resolve the diffs between orig and recomp by patching
    swapped fld/fmul instructions?
    For example:
        fld [ebp - 4]                   fmul [ebp - 8]
        fld [ebp - 8]                   fmul [ebp - 4]

    Returns set of fixed lines
    """

    valid_following_ops = ["fmul", "fadd"]

    # find the first "fld" instruction
    fld_index = next((i for i, s in enumerate(orig) if s.startswith("fld")), -1)
    # return if not found, or only found on the last line
    if (
        fld_index in (-1, len(orig) - 1)
        or fld_index >= len(recomp) - 1
        or
        # recomp should also have a fld in the same line
        not recomp[fld_index].startswith("fld")
    ):
        return set()

    _, _, orig_operand_a = orig[fld_index].partition(" ")
    orig_mnemonic_b, _, orig_operand_b = orig[fld_index + 1].partition(" ")

    _, _, recomp_operand_a = recomp[fld_index].partition(" ")
    recomp_mnemonic_b, _, recomp_operand_b = recomp[fld_index + 1].partition(" ")

    # fld must be followed by fmul/fadd and orig and recomp must have the same mnenomic
    # and the operands must be swapped
    if (
        orig_mnemonic_b in valid_following_ops
        and orig_mnemonic_b == recomp_mnemonic_b
        and orig_operand_a == recomp_operand_b
        and orig_operand_b == recomp_operand_a
    ):
        return {fld_index, fld_index + 1}

    return set()


# Matches the displacement (symbol or offset) of a memory operand:
# the final term inside the brackets, e.g. `g_table (DATA)` in
# `fld dword ptr [edx*4 + g_table (DATA)]`.
DISPLACEMENT_RE = re.compile(r"[+-] ?(.+)\]$")
BRACKET_RE = re.compile(r"\[(.+)\]$")

COMMUTATIVE_X87_MNEMONICS = ("fadd", "fmul")


def _displacement_parts(line: str) -> tuple[str, str | None]:
    """Split an instruction into (skeleton, displacement) where the
    displacement is the last term of its memory operand. The skeleton is
    the line with the displacement replaced by a placeholder."""
    match = DISPLACEMENT_RE.search(line) or BRACKET_RE.search(line)
    if match is None:
        return line, None

    return line[: match.start(1)] + "?" + line[match.end(1) :], match.group(1)


def is_commutative_x87_chain_swap(orig_asm: list[str], recomp_asm: list[str]) -> bool:
    """MSVC nondeterministically swaps the two operand chains of a commutative
    x87 computation between recompiles. For example, `tableA[i] + tableB[j]`:

        mov eax, [ecx + 0x94]               mov eax, [ecx + 0x9c]
        movsx edx, word ptr [eax + 0xc]     movsx edx, word ptr [eax + 0xc]
        mov eax, [ecx + 0x9c]               mov eax, [ecx + 0x94]
        fld dword ptr [edx*4 + tableA]      fld dword ptr [edx*4 + tableB]
        movsx ecx, word ptr [eax + 0xc]     movsx ecx, word ptr [eax + 0xc]
        fadd dword ptr [ecx*4 + tableB]     fadd dword ptr [ecx*4 + tableA]
        ret                                 ret

    fadd/fmul are commutative so both versions are equivalent. Detect this
    shape: the fld and the fadd/fmul swap their memory displacements while
    the index registers stay put, and the address-load movs that feed the
    two chains transpose as exact-text pairs."""
    if len(orig_asm) != len(recomp_asm):
        return False

    diff_idx = [i for i, (a, b) in enumerate(zip(orig_asm, recomp_asm)) if a != b]
    if not diff_idx:
        return False

    flds = [
        i
        for i in diff_idx
        if _mnemonic(orig_asm[i]) == "fld" and _mnemonic(recomp_asm[i]) == "fld"
    ]
    comms = [
        i
        for i in diff_idx
        if _mnemonic(orig_asm[i]) in COMMUTATIVE_X87_MNEMONICS
        and _mnemonic(recomp_asm[i]) == _mnemonic(orig_asm[i])
    ]
    if len(flds) != 1 or len(comms) != 1:
        return False

    fld_idx, comm_idx = flds[0], comms[0]
    if comm_idx < fld_idx:
        return False

    # The swap is only sound if nothing touches the x87 stack between the
    # fld and the commutative op (e.g. an fsqrt would make the two operand
    # orders produce different results).
    if any(
        _mnemonic(orig_asm[k]).startswith("f") for k in range(fld_idx + 1, comm_idx)
    ):
        return False

    orig_fld, orig_fld_disp = _displacement_parts(orig_asm[fld_idx])
    orig_comm, orig_comm_disp = _displacement_parts(orig_asm[comm_idx])
    recomp_fld, recomp_fld_disp = _displacement_parts(recomp_asm[fld_idx])
    recomp_comm, recomp_comm_disp = _displacement_parts(recomp_asm[comm_idx])

    if None in (orig_fld_disp, orig_comm_disp, recomp_fld_disp, recomp_comm_disp):
        return False

    # Only the displacements may differ, and they must be cross-swapped.
    if orig_fld != recomp_fld or orig_comm != recomp_comm:
        return False

    if not (orig_fld_disp == recomp_comm_disp and orig_comm_disp == recomp_fld_disp):
        return False

    # Every other differing line must be part of the operand-chain setup:
    # a mov before the fld, transposed with an identical-text partner.
    remaining = [k for k in diff_idx if k not in (fld_idx, comm_idx)]
    if any(
        k > fld_idx
        or _mnemonic(orig_asm[k]) != "mov"
        or _mnemonic(recomp_asm[k]) != "mov"
        for k in remaining
    ):
        return False

    return sorted(orig_asm[k] for k in remaining) == sorted(
        recomp_asm[k] for k in remaining
    )


_REG_ALIASES: dict[str, tuple[str, ...]] = {}
for _r in "abcd":
    _fam = (f"e{_r}x", f"{_r}x", f"{_r}l", f"{_r}h")
    for _n in _fam:
        _REG_ALIASES[_n] = _fam
for _r2 in ("si", "di", "bp", "sp"):
    _fam2 = (f"e{_r2}", _r2)
    for _n in _fam2:
        _REG_ALIASES[_n] = _fam2


def _register_reused_later(asm: list[str], start: int, reg: str) -> bool:
    """Textual liveness scan: is `reg` (or an aliasing sub-register) read
    at or after `start`, before being redefined? Conservative: any
    appearance that is not a plain redefinition counts as a use."""
    aliases = _REG_ALIASES.get(reg)
    if aliases is None:
        return False
    pattern = re.compile(r"\b(?:" + "|".join(aliases) + r")\b")
    for line in asm[start:]:
        mnemonic, _, op_str = line.partition(" ")
        first, _, rest = op_str.partition(", ")
        if (
            mnemonic in ("mov", "lea", "pop")
            and first == reg
            and not pattern.search(rest)
        ):
            return False
        if pattern.search(line):
            return True
    return False


def _mov_temp_is_dead(
    orig_asm: list[str], recomp_asm: list[str], i: int, j: int
) -> bool:
    """For a mov/cmp/jmp patch with the mov at orig index i / recomp index j:
    the swap is only sound if the mov's destination register is dead after
    the jump. (GH: reusing the temp after the branch changes behavior.)"""
    orig_reg = orig_asm[i].partition(" ")[2].partition(",")[0].strip()
    recomp_reg = recomp_asm[j].partition(" ")[2].partition(",")[0].strip()
    return not _register_reused_later(
        orig_asm, i + 3, orig_reg
    ) and not _register_reused_later(recomp_asm, j + 3, recomp_reg)


def patch_cmp_swaps(
    codes: Sequence[DiffOpcode], orig_asm: list[str], recomp_asm: list[str]
) -> set[int]:
    """Can we resolve the diffs between orig and recomp by patching
    swapped cmp instructions?
    """

    # number of additional lines to send to the patcher when considering each diff
    additonal_lines_to_include = 3

    fixed_lines = set()

    patch_fns = [
        patch_cmp_jmp,
        patch_test_jmp,
        patch_mov_cmp_jmp,
        patch_mov_test_jmp,
        patch_fld_fmul,
        patch_mov_commutative,
    ]

    for code, i1, i2, j1, j2 in codes:
        # To save us the trouble of finding "compatible" cmp instructions
        # use the diff information we already have.
        if code != "replace":
            continue

        # If the ranges in orig and recomp are not equal, use the shorter one
        for i, j in zip(range(i1, i2), range(j1, j2)):
            for fn in patch_fns:
                this_patch_lines = fn(
                    orig_asm[i : i + additonal_lines_to_include],
                    recomp_asm[j : j + additonal_lines_to_include],
                )
                # The mov/cmp/jmp patch loads different values into the
                # temporary register on each side, so it is only valid
                # if the register is not read again after the jump.
                if (
                    len(this_patch_lines) > 0
                    and fn in (patch_mov_cmp_jmp, patch_mov_test_jmp)
                    and not _mov_temp_is_dead(orig_asm, recomp_asm, i, j)
                ):
                    this_patch_lines = set()

                # if we have fixed lines by this patcher, add them to the combined `fixed_lines`
                if len(this_patch_lines) > 0:
                    fixed_lines.update([j + x for x in this_patch_lines])
                    # now that we've fixed these lines, no need to check the other patch strategies for fixing
                    break

    return fixed_lines


def effective_match_possible(orig_asm: list[str], recomp_asm: list[str]) -> bool:
    # We can only declare an effective match based on the text
    # so you need the same amount of "stuff" in each
    if len(orig_asm) != len(recomp_asm):
        return False

    # mnemonic_orig = [inst.partition(" ")[0] for inst in orig_asm]
    # mnemonic_recomp = [inst.partition(" ")[0] for inst in recomp_asm]

    # Cannot change mnemonics. Must be same starting list
    # TODO: Fine idea but this will exclude jump swaps for cmp operand order
    # if sorted(mnemonic_orig) != sorted(mnemonic_recomp):
    #    return False

    return True


def _is_relocatable(instr: str) -> bool:
    """
    Excludes certain instructions whose relocation will always change the logic
    to be considered for an effective match.
    """
    if instr.startswith("start +"):
        # Do not relocate jump table entries (this most likely influences the behaviour)
        return False
    if instr.startswith("0x"):
        # Do not relocate data table entries (this most likely influences the behaviour)
        return False
    return True


def relocate_instructions(
    codes: Sequence[DiffOpcode], orig_asm: list[str], recomp_asm: list[str]
) -> set[int]:
    """Collect the list of instructions deleted from orig and inserted
    into recomp, according to the diff opcodes. Using this list, match up
    any pairs of instructions that we assume to be relocated and return
    the indices in recomp where this has occurred.

    A move is only accepted when the instruction is independent of every
    instruction it crosses: no register read/write conflicts, no flag
    dependencies, no possibly-aliasing memory access, no x87 stack
    interaction and no control-flow barrier in between. (GH #324)
    """
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

    relocated = set()

    for orig_dest, j in inserts:
        line = recomp_asm[j]
        if not _is_relocatable(line):
            continue
        moved = line_effects(line)
        if moved.barrier:
            continue
        for i in deletes:
            # Check for exact match.
            if orig_asm[i] != line:
                continue
            # To account for a move in either direction:
            # the deleted line can precede or follow the inserted line.
            reloc_start = min(i, orig_dest)
            reloc_end = max(i, orig_dest)

            crossed = [orig_asm[k] for k in range(reloc_start, reloc_end) if k != i]
            if any(effects_conflict(moved, line_effects(other)) for other in crossed):
                continue

            # If both the moved instruction and a crossed instruction write
            # the flags, the move changes which value the flags hold at the
            # end of the region: the flags must be dead there.
            if moved.writes_flags and any(
                line_effects(other).writes_flags for other in crossed
            ):
                after = reloc_end + 1 if reloc_end == i else reloc_end
                if not flags_dead_at(orig_asm, after):
                    continue

            relocated.add(j)
            deletes.remove(i)
            break

    return relocated


DWORD_REGS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
WORD_REGS = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")
BYTE_REGS = ("ah", "al", "bh", "bl", "ch", "cl", "dh", "dl")
REGISTER_SET = set(reg for reg in (DWORD_REGS + WORD_REGS + BYTE_REGS))


def find_effective_match(
    codes: Sequence[DiffOpcode], orig_asm: list[str], recomp_asm: list[str]
) -> bool:
    """Check whether the two sequences of instructions are an effective match.
    Meaning: do they differ only by instruction order or register selection?"""
    if not effective_match_possible(orig_asm, recomp_asm):
        return False

    # The relational verifier proves equivalence modulo register allocation,
    # commutative-operand order and inverted compare/jump conditions.
    if verify_effective_match(orig_asm, recomp_asm):
        return True

    # Whole-function check: commutative x87 operand-chain swap.
    # (Usually subsumed by the verifier; kept for chains it cannot model.)
    if is_commutative_x87_chain_swap(orig_asm, recomp_asm):
        return True

    # Fallback for instruction-scheduling differences, which the lockstep
    # verifier cannot prove, possibly combined with local swap patches.
    recomp_lines_disputed = {
        j
        for code, _, __, j1, j2 in codes
        for j in range(j1, j2)
        if code in ("insert", "replace")
    }

    cmp_swaps = patch_cmp_swaps(codes, orig_asm, recomp_asm)
    relocates = relocate_instructions(codes, orig_asm, recomp_asm)

    corrections = cmp_swaps.union(relocates)

    return corrections.issuperset(recomp_lines_disputed)


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
