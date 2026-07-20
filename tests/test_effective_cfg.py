"""Tests for CFG-aware relational effective-match verification."""

from difflib import SequenceMatcher

from reccmp.compare.asm.effective import (
    FunctionMetadata,
    verify_cfg_effective_match,
    verify_effective_match,
)
from reccmp.compare.asm.fixes import find_effective_match
from reccmp.compare.asm.instgen import InstructionMeta


def test_cfg_rename_live_across_branch():
    """A renamed temp may remain live across a branch and its join."""
    orig = [
        "mov eax, dword ptr [ebp - 4]",
        "cmp edx, 0",
        "je 0x2",
        "inc edx",
        "mov dword ptr [esi], eax",
        "ret",
    ]
    recomp = [
        "mov ecx, dword ptr [ebp - 4]",
        "cmp edx, 0",
        "je 0x2",
        "inc edx",
        "mov dword ptr [esi], ecx",
        "ret",
    ]
    targets = [None, None, 4, None, None, None]
    metadata = FunctionMetadata(return_kind="void")
    assert verify_effective_match(orig, recomp, metadata=metadata) is True
    assert verify_cfg_effective_match(orig, recomp, targets, targets, metadata) is True


def test_cfg_commutative_x87_across_branch():
    """Path-local memory generations preserve a pending x87 operand swap."""
    orig = [
        "fld dword ptr [g_a (DATA)]",
        "cmp edx, 0",
        "je 0x2",
        "inc edx",
        "fadd dword ptr [g_b (DATA)]",
        "fstp dword ptr [esi]",
        "ret",
    ]
    recomp = [
        "fld dword ptr [g_b (DATA)]",
        "cmp edx, 0",
        "je 0x2",
        "inc edx",
        "fadd dword ptr [g_a (DATA)]",
        "fstp dword ptr [esi]",
        "ret",
    ]
    targets = [None, None, 4, None, None, None, None]
    metadata = FunctionMetadata(return_kind="void")
    assert verify_effective_match(orig, recomp, metadata=metadata) is False
    assert verify_cfg_effective_match(orig, recomp, targets, targets, metadata) is True


def test_cfg_rejects_divergent_branch_arm():
    """A later textual overwrite must not hide a return on another arm."""
    orig = [
        "cmp ecx, 0",
        "je 0x6",
        "mov eax, 1",
        "jmp 0x2",
        "mov eax, 3",
        "ret",
    ]
    recomp = [
        "cmp ecx, 0",
        "je 0x6",
        "mov eax, 2",
        "jmp 0x2",
        "mov eax, 3",
        "ret",
    ]
    targets = [None, 4, None, 5, None, None]
    assert verify_cfg_effective_match(orig, recomp, targets, targets) is False


def test_cfg_rejects_divergence_reaching_join():
    """A differing value from one arm remains poison after the join."""
    orig = [
        "cmp ecx, 0",
        "je 0x6",
        "mov eax, 1",
        "jmp 0x2",
        "mov eax, 3",
        "mov dword ptr [esi], eax",
        "ret",
    ]
    recomp = [
        "cmp ecx, 0",
        "je 0x6",
        "mov eax, 2",
        "jmp 0x2",
        "mov eax, 3",
        "mov dword ptr [esi], eax",
        "ret",
    ]
    targets = [None, 4, None, 5, None, None, None]
    metadata = FunctionMetadata(return_kind="void")
    assert verify_cfg_effective_match(orig, recomp, targets, targets, metadata) is False


def test_cfg_accepts_identical_diamond():
    orig = [
        "cmp ecx, 0",
        "je 0x6",
        "mov eax, 1",
        "jmp 0x2",
        "mov eax, 3",
        "mov dword ptr [esi], eax",
        "ret",
    ]
    targets = [None, 4, None, 5, None, None, None]
    metadata = FunctionMetadata(return_kind="void")
    assert (
        verify_cfg_effective_match(orig, list(orig), targets, targets, metadata) is True
    )


def test_cfg_rejects_structural_difference():
    """Branches that target different lines are a real difference."""
    orig = ["cmp ecx, 0", "je 0x4", "inc edx", "inc edx", "ret"]
    recomp = ["cmp ecx, 0", "je 0x4", "inc edx", "inc edx", "ret"]
    assert (
        verify_cfg_effective_match(
            orig, recomp, [None, 3, None, None, None], [None, 4, None, None, None]
        )
        is False
    )


def test_cfg_canonicalizes_branch_displacements():
    """Rendered displacements are irrelevant when block targets agree."""
    orig = ["cmp ecx, 0", "je 0x2", "inc edx", "ret"]
    recomp = ["cmp ecx, 0", "je 0x20", "inc edx", "ret"]
    targets = [None, 3, None, None]
    metadata = FunctionMetadata(return_kind="void")
    assert verify_cfg_effective_match(orig, recomp, targets, targets, metadata) is True


def test_find_effective_match_uses_structured_branch_targets():
    """The wrapper threads both address spaces into the private CFG proof."""
    orig = ["cmp ecx, 0", "je 0x2", "inc edx", "ret"]
    recomp = ["cmp ecx, 0", "je 0x20", "inc edx", "ret"]
    orig_addrs = [0x1000, 0x1002, 0x1004, 0x1005]
    recomp_addrs = [0x2000, 0x2002, 0x2004, 0x2005]

    def jump_meta(address: int, target: int) -> InstructionMeta:
        return InstructionMeta(
            address=address,
            size=2,
            mnemonic="je",
            regs_read=("eflags",),
            regs_written=(),
            reads_flags=True,
            writes_flags=False,
            accesses_memory=False,
            is_jump=True,
            is_call=False,
            is_ret=False,
            branch_target=target,
        )

    orig_meta = [None, jump_meta(0x1002, 0x1005), None, None]
    recomp_meta = [None, jump_meta(0x2002, 0x2005), None, None]
    codes = SequenceMatcher(None, orig, recomp).get_opcodes()
    assert (
        find_effective_match(
            codes,
            orig,
            recomp,
            orig_addrs=orig_addrs,
            recomp_addrs=recomp_addrs,
            metadata=FunctionMetadata(return_kind="void"),
            orig_meta=orig_meta,
            recomp_meta=recomp_meta,
        )
        is True
    )


def test_cfg_loop_with_identical_body():
    """A backward edge reaches a bounded symbolic fixpoint."""
    orig = [
        "xor eax, eax",
        "add eax, 1",
        "cmp eax, 0x10",
        "jl -0x5",
        "mov dword ptr [esi], eax",
        "ret",
    ]
    targets = [None, None, None, 1, None, None]
    metadata = FunctionMetadata(return_kind="void")
    assert (
        verify_cfg_effective_match(orig, list(orig), targets, targets, metadata) is True
    )


def test_cfg_rejects_computed_jump_with_divergence():
    """Computed jump destinations are not paired by this CFG proof."""
    orig = [
        "mov eax, dword ptr [ebp - 4]",
        "jmp dword ptr [eax*4 + <OFFSET1>]",
    ]
    recomp = [
        "mov ecx, dword ptr [ebp - 4]",
        "jmp dword ptr [ecx*4 + <OFFSET1>]",
    ]
    targets: list[int | None] = [None, None]
    assert verify_cfg_effective_match(orig, recomp, targets, targets) is False


def test_cfg_rejects_divergent_state_at_external_jump():
    """Code outside the paired CFG can observe every physical register."""
    orig = ["mov ebx, 1", "jmp target (FUNCTION)"]
    recomp = ["mov ebx, 2", "jmp target (FUNCTION)"]
    targets: list[int | None] = [None, None]
    assert verify_cfg_effective_match(orig, recomp, targets, targets) is False


def test_cfg_rejects_divergent_state_on_external_conditional_edge():
    """The taken edge is checked before a fallthrough overwrite."""
    orig = [
        "mov eax, 1",
        "cmp ecx, 0",
        "je target (FUNCTION)",
        "xor eax, eax",
        "ret",
    ]
    recomp = [
        "mov eax, 2",
        "cmp ecx, 0",
        "je target (FUNCTION)",
        "xor eax, eax",
        "ret",
    ]
    targets: list[int | None] = [None] * len(orig)
    metadata = FunctionMetadata(return_kind="void")
    assert verify_cfg_effective_match(orig, recomp, targets, targets, metadata) is False
