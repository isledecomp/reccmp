import difflib
from reccmp.compare.asm.fixes import (
    find_effective_match,
    patch_compare_jmp,
    patch_fld_fmul,
    patch_mov_compare_jmp,
)


def test_fix_cmp_jmp():
    orig_asm = ["mov eax, 1", "mov ebx, 2", "cmp eax, ebx", "jg 0x1"]
    recomp_asm = ["mov eax, 1", "mov ebx, 2", "cmp ebx, eax", "jl 0x1"]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is True


def test_fix_test_jmp():
    """`test` is commutative: swapping its operands produces identical flags.
    An identical jump is therefore an effective match..."""
    orig_asm = ["mov eax, 1", "mov ebx, 2", "test eax, ebx", "jg 0x1"]
    recomp_asm = ["mov eax, 1", "mov ebx, 2", "test ebx, eax", "jg 0x1"]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is True


def test_fix_test_jmp_inverted_jump_invalid():
    """...but an inverted jump is not. Because the flags are the same either
    way, jg and jl react differently to them. (This was previously accepted:
    a false positive of the swapped-cmp patch.)"""
    orig_asm = ["mov eax, 1", "mov ebx, 2", "test eax, ebx", "jg 0x1"]
    recomp_asm = ["mov eax, 1", "mov ebx, 2", "test ebx, eax", "jl 0x1"]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_fix_mov_cmp_jmp_mem_with_different_operands():
    """This should not be fixed up, since the operands are different"""
    orig_asm = [
        "mov eax, dword ptr [ebp-4]",
        "cmp dword ptr [global_var_1 (DATA)], eax",
        "jne 0x1",
    ]
    recomp_asm = [
        "mov eax, dword ptr [global_var_2 (DATA)]",
        "cmp dword ptr [ebp-4], eax",
        "jne 0x1",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_fix_mov_cmp_jmp_mem_with_non_matching_jmp():

    orig_asm = [
        "mov eax, dword ptr [ebp-4]",
        "cmp dword ptr [gCurrent_key (DATA)], eax",
        "jl 0x1",
    ]
    recomp_asm = [
        "mov eax, [gCurrent_key (DATA)]",
        "cmp dword ptr [ebp-4], eax",
        "jl 0x1",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_fix_mov_cmp_jmp_mem_with_non_matching_jmp_2():

    orig_asm = [
        "mov eax, dword ptr [ebp-4]",
        "cmp dword ptr [gCurrent_key (DATA)], eax",
        "jg 0x1",
    ]
    recomp_asm = [
        "mov eax, [gCurrent_key (DATA)]",
        "cmp dword ptr [ebp-4], eax",
        "jle 0x1",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_fix_mov_cmp_jmp_mem_valid():

    orig_asm = [
        "mov eax, dword ptr [ebp-4]",
        "cmp dword ptr [gCurrent_key (DATA)], eax",
        "jne 0x1",
    ]
    recomp_asm = [
        "mov eax, dword ptr [gCurrent_key (DATA)]",
        "cmp dword ptr [ebp-4], eax",
        "jne 0x1",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is True


def test_fix_mov_test_jmp_mem_valid():

    orig_asm = [
        "mov eax, dword ptr [ebp-4]",
        "test dword ptr [gCurrent_key (DATA)], eax",
        "jne 0x1",
    ]
    recomp_asm = [
        "mov eax, dword ptr [gCurrent_key (DATA)]",
        "test dword ptr [ebp-4], eax",
        "jne 0x1",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is True


def test_fix_fld_fmul_valid():

    orig_asm = [
        "fld dword ptr [ebp - 0x18]",
        "fmul dword ptr [ebp - 8]",
        "faddp st(1)",
        "fld dword ptr [ebp - 4]",
        "fadd dword ptr [ebp - 0x14]",
    ]
    recomp_asm = [
        "fld dword ptr [ebp - 8]",
        "fmul dword ptr [ebp - 0x18]",
        "faddp st(1)",
        "fld dword ptr [ebp - 0x14]",
        "fadd dword ptr [ebp - 4]",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is True


def test_fix_fld_fadd_fsub():

    orig_asm = [
        "fld dword ptr [ebp - 0x18]",
        "fadd dword ptr [ebp - 8]",
    ]
    recomp_asm = ["fld dword ptr [ebp - 8]", "fsub dword ptr [ebp - 0x18]"]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_fix_fld_fadd_with_instruction_between():

    orig_asm = [
        "fld dword ptr [ebp - 0x18]",
        "mov eax, 1",
        "fadd dword ptr [ebp - 8]",
    ]
    recomp_asm = ["fld dword ptr [ebp - 8]", "fadd dword ptr [ebp - 0x18]"]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False

    # fadd is commutative, so swapped operands with an intervening
    # non-x87 instruction are an effective match
    # (via is_commutative_x87_chain_swap).
    orig_asm = [
        "fld dword ptr [ebp - 0x18]",
        "mov eax, 1",
        "fadd dword ptr [ebp - 8]",
    ]
    recomp_asm = [
        "fld dword ptr [ebp - 8]",
        "mov eax, 1",
        "fadd dword ptr [ebp - 0x18]",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is True


def test_fix_fld_fmul_invalid_duplication():

    orig_asm = [
        "fld dword ptr [ebp - 0x18]",
        "fmul dword ptr [ebp - 8]",
        "fld dword ptr [ebp - 0x18]",
        "fmul dword ptr [ebp - 8]",
    ]
    recomp_asm = [
        "fld dword ptr [ebp - 8]",
        "fmul dword ptr [ebp - 0x18]",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_fix_fld_fmul_invalid_diff_operands():

    orig_asm = [
        "fld dword ptr [ebp - 0x18]",
        "fmul dword ptr [ebp - 9]",
    ]
    recomp_asm = [
        "fld dword ptr [ebp - 8]",
        "fmul dword ptr [ebp - 0x18]",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_fix_fld_fsub_invalid():

    orig_asm = [
        "fld dword ptr [ebp - 0x18]",
        "fsub dword ptr [ebp - 8]",
    ]
    recomp_asm = [
        "fld dword ptr [ebp - 8]",
        "fsub dword ptr [ebp - 0x18]",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_fix_mov_imul_swap_valid():

    orig_asm = [
        "mov eax, dword ptr [ebp - 0x4]",
        "imul eax, dword ptr [ebp - 0x8]",
    ]
    recomp_asm = [
        "mov eax, dword ptr [ebp - 0x8]",
        "imul eax, dword ptr [ebp - 0x4]",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is True


def test_fix_mov_imul_single_operand_imul():
    """Single-operand IMUL multiplies into AX (for a word operand), and
    multiplication is commutative, so loading the other factor first is an
    effective match."""

    orig_asm = [
        "mov ax, word ptr [ebp - 0x4]",
        "imul word ptr [ebp - 0x8]",
    ]
    recomp_asm = [
        "mov ax, word ptr [ebp - 0x8]",
        "imul word ptr [ebp - 0x4]",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is True


def test_fix_mov_add_swap_valid():

    orig_asm = [
        "mov eax, dword ptr [ebp - 0x4]",
        "add eax, dword ptr [ebp - 0x8]",
    ]
    recomp_asm = [
        "mov eax, dword ptr [ebp - 0x8]",
        "add eax, dword ptr [ebp - 0x4]",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is True


def test_fix_mov_add_swap_with_literal_valid():

    orig_asm = [
        "mov eax, 1",
        "add eax, dword ptr [ebp - 0x8]",
    ]
    recomp_asm = [
        "mov eax, dword ptr [ebp - 0x8]",
        "add eax, 1",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is True


def test_fix_mov_add_swap_on_stack_invalid():

    orig_asm = [
        "mov dword ptr [ebp - 0x4], 1",
        "add dword ptr [ebp - 0x4], 2",
    ]
    recomp_asm = [
        "mov dword ptr [ebp - 0x4], 2",
        "add dword ptr [ebp - 0x4], 1",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    # Pretty sure this is actually safe, but not implemented
    assert is_effective is False


def test_fix_mov_sub_swap_invalid():

    orig_asm = [
        "mov eax, dword ptr [ebp - 0x4]",
        "sub eax, dword ptr [ebp - 0x8]",
    ]
    recomp_asm = [
        "mov eax, dword ptr [ebp - 0x8]",
        "sub eax, dword ptr [ebp - 0x4]",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    # Like the add/imul tests except subtraction is NOT commutative
    assert is_effective is False


def test_fix_mov_add_invalid_dest():

    orig_asm = [
        "mov eax, dword ptr [ebp - 0x4]",
        "add eax, dword ptr [ebp - 0x8]",
    ]
    recomp_asm = [
        "mov eax, dword ptr [ebp - 0x8]",
        "add ebx, dword ptr [ebp - 0x4]",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_this_should_not_be_marked_as_effective():
    """The instructions `mov eax, 0` and `mov ecx, 1` cannot have their registers swapped."""

    orig_asm = [
        "mov eax, dword ptr [esi + 0x100]",
        "mov ecx, dword ptr [eax + 0x74]",
        "add eax, 0x74",
        "sub ecx, 3",
        "cmp ecx, 0xc",
        "ja 0x0",
        "mov eax, 0",
        "mov ecx, 1",
        "mov dword ptr [eax], 2",
    ]
    recomp_asm = [
        "mov ecx, dword ptr [esi + 0x100]",
        "mov eax, dword ptr [ecx + 0x74]",
        "add ecx, 0x74",
        "sub eax, 3",
        "cmp eax, 0xc",
        "ja 0x0",
        "mov eax, 0",
        "mov ecx, 1",
        "mov dword ptr [ecx], 2",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_fix_mov_cmp_jmp_unsafe_intermediate_reuse():
    # These are NOT equivalent since eax is used after the jmp
    orig_asm = [
        "mov eax, dword ptr [ebp - 8]",
        "cmp eax, dword ptr [ebp - 4]",
        "jl 0x2",
        "mov dword ptr [ebp - 0xc], eax",
    ]
    recomp_asm = [
        "mov eax, dword ptr [ebp - 4]",
        "cmp eax, dword ptr [ebp - 8]",
        "jg 0x2",
        "mov dword ptr [ebp - 0xc], eax",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_and_swap_not_allowed():
    """Cannot move the `and eax, 0xff` instruction for an effective match.
    `eax` is modified by the intermediate instructions. (GH #322)"""

    orig_asm = [
        "mov eax, dword ptr [ebp - 4]",
        "and eax, 0xff",  # Move this
        "mov ecx, dword ptr [gReal_render_palette (DATA)]",
        "mov eax, dword ptr [ecx + eax*4]",
        # To here
        "mov ecx, dword ptr [gRender_palette (DATA)]",
    ]

    recomp_asm = [
        "mov eax, dword ptr [ebp - 4]",
        "mov ecx, dword ptr [gReal_render_palette (DATA)]",
        "mov eax, dword ptr [ecx + eax*4]",
        "and eax, 0xff",
        "mov ecx, dword ptr [gRender_palette (DATA)]",
    ]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is False


def test_patch_compare_jmp_cmp_recomp_shorter_than_orig():
    """Regression: cmp_index found in orig must be bounds-checked against recomp
    before indexing recomp[cmp_index]. Previously raised IndexError."""
    orig = ["mov eax, 1", "mov ebx, 2", "cmp eax, ebx", "jg 0x1"]
    recomp = ["mov eax, 1", "mov ebx, 2"]
    assert patch_compare_jmp(orig, recomp, "cmp") == set()


def test_patch_compare_jmp_test_recomp_shorter_than_orig():
    orig = ["mov eax, 1", "mov ebx, 2", "test eax, ebx", "jg 0x1"]
    recomp = ["mov eax, 1", "mov ebx, 2"]
    assert patch_compare_jmp(orig, recomp, "test") == set()


def test_patch_mov_compare_jmp_recomp_shorter_than_orig():
    orig = [
        "mov eax, dword ptr [ebp - 4]",
        "cmp dword ptr [ebp - 8], eax",
        "jl 0x1",
    ]
    recomp = ["mov eax, dword ptr [ebp - 4]"]
    assert patch_mov_compare_jmp(orig, recomp, "cmp") == set()


def test_patch_fld_fmul_recomp_shorter_than_orig():
    orig = ["fld dword ptr [ebp - 4]", "fmul dword ptr [ebp - 8]"]
    recomp = ["fld dword ptr [ebp - 4]"]
    assert patch_fld_fmul(orig, recomp) == set()


# The following tests cover is_commutative_x87_chain_swap: MSVC
# nondeterministically swaps the operand chains of commutative x87
# computations (e.g. tableA[i] + tableB[j]) between recompiles.
# The asm below is the real shape of Imperialism 0x4e0590 after sanitization.

X87_CHAIN_ORIG = [
    "mov eax, dword ptr [ecx + 0x94]",
    "movsx edx, word ptr [eax + 0xc]",
    "mov eax, dword ptr [ecx + 0x9c]",
    "fld dword ptr [edx*4 + g_skillTableA (DATA)]",
    "movsx ecx, word ptr [eax + 0xc]",
    "fadd dword ptr [ecx*4 + g_skillTableB (DATA)]",
    "ret",
]

X87_CHAIN_RECOMP = [
    "mov eax, dword ptr [ecx + 0x9c]",
    "movsx edx, word ptr [eax + 0xc]",
    "mov eax, dword ptr [ecx + 0x94]",
    "fld dword ptr [edx*4 + g_skillTableB (DATA)]",
    "movsx ecx, word ptr [eax + 0xc]",
    "fadd dword ptr [ecx*4 + g_skillTableA (DATA)]",
    "ret",
]


def test_commutative_x87_chain_swap_valid():
    """The fld/fadd displacements are cross-swapped and the two
    address-load movs transpose: an effective match."""
    diff = difflib.SequenceMatcher(None, X87_CHAIN_ORIG, X87_CHAIN_RECOMP)
    assert (
        find_effective_match(diff.get_opcodes(), X87_CHAIN_ORIG, X87_CHAIN_RECOMP)
        is True
    )


def test_commutative_x87_chain_swap_fsub_invalid():
    """fsub is not commutative: must not be an effective match."""
    recomp = list(X87_CHAIN_RECOMP)
    recomp[5] = "fsub dword ptr [ecx*4 + g_skillTableA (DATA)]"

    diff = difflib.SequenceMatcher(None, X87_CHAIN_ORIG, recomp)
    assert find_effective_match(diff.get_opcodes(), X87_CHAIN_ORIG, recomp) is False


def test_commutative_x87_chain_swap_mov_not_transposed():
    """A mov that differs without a transposed partner is a real diff."""
    recomp = list(X87_CHAIN_RECOMP)
    recomp[0] = "mov eax, dword ptr [ecx + 0xa0]"

    diff = difflib.SequenceMatcher(None, X87_CHAIN_ORIG, recomp)
    assert find_effective_match(diff.get_opcodes(), X87_CHAIN_ORIG, recomp) is False


def test_commutative_x87_chain_swap_x87_instruction_between():
    """An x87 instruction between the fld and the fadd modifies st(0),
    so the operand order matters: must not be an effective match."""
    orig = [
        "fld dword ptr [g_floatA (FLOAT)]",
        "fsqrt",
        "fadd dword ptr [g_floatB (FLOAT)]",
        "ret",
    ]
    recomp = [
        "fld dword ptr [g_floatB (FLOAT)]",
        "fsqrt",
        "fadd dword ptr [g_floatA (FLOAT)]",
        "ret",
    ]

    diff = difflib.SequenceMatcher(None, orig, recomp)
    assert find_effective_match(diff.get_opcodes(), orig, recomp) is False


def test_commutative_x87_chain_swap_index_registers_stay():
    """Only the displacements swap; if the index registers differ too,
    the skeletons don't match and this is a real diff."""
    recomp = list(X87_CHAIN_RECOMP)
    recomp[3] = "fld dword ptr [eax*4 + g_skillTableB (DATA)]"

    diff = difflib.SequenceMatcher(None, X87_CHAIN_ORIG, recomp)
    assert find_effective_match(diff.get_opcodes(), X87_CHAIN_ORIG, recomp) is False


def test_commutative_x87_chain_swap_mov_after_fld_invalid():
    """A differing mov after the fld is not operand-chain setup."""
    orig = [
        "mov eax, dword ptr [ecx + 0x94]",
        "fld dword ptr [g_floatA (FLOAT)]",
        "mov edx, dword ptr [ecx + 0x9c]",
        "fadd dword ptr [g_floatB (FLOAT)]",
        "ret",
    ]
    recomp = [
        "mov eax, dword ptr [ecx + 0x9c]",
        "fld dword ptr [g_floatB (FLOAT)]",
        "mov edx, dword ptr [ecx + 0x94]",
        "fadd dword ptr [g_floatA (FLOAT)]",
        "ret",
    ]

    diff = difflib.SequenceMatcher(None, orig, recomp)
    assert find_effective_match(diff.get_opcodes(), orig, recomp) is False


# The following tests cover the dependency-aware relocate_instructions:
# an instruction may only move across instructions it does not depend on.


def _diff_and_match(orig_asm: list[str], recomp_asm: list[str]) -> bool:
    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    return find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)


def test_relocate_independent_load():
    """Two independent loads scheduled in opposite order."""
    orig_asm = [
        "mov eax, dword ptr [ebp - 4]",
        "mov ecx, dword ptr [ebp - 8]",
        "push ecx",
        "push eax",
        "call <OFFSET1>",
    ]
    recomp_asm = [
        "mov ecx, dword ptr [ebp - 8]",
        "mov eax, dword ptr [ebp - 4]",
        "push ecx",
        "push eax",
        "call <OFFSET1>",
    ]
    assert _diff_and_match(orig_asm, recomp_asm) is True


def test_relocate_rejects_store_across_aliasing_load():
    """A store may not move across a load of the same address."""
    orig_asm = [
        "mov dword ptr [ebp - 4], eax",
        "mov ecx, dword ptr [ebp - 4]",
        "push ecx",
        "push esi",
    ]
    recomp_asm = [
        "mov ecx, dword ptr [ebp - 4]",
        "mov dword ptr [ebp - 4], eax",
        "push ecx",
        "push esi",
    ]
    assert _diff_and_match(orig_asm, recomp_asm) is False


def test_relocate_store_across_disjoint_frame_slot():
    """Stores to provably distinct ebp frame slots may reorder."""
    orig_asm = [
        "mov dword ptr [ebp - 4], eax",
        "mov dword ptr [ebp - 8], ecx",
        "push esi",
        "push edi",
    ]
    recomp_asm = [
        "mov dword ptr [ebp - 8], ecx",
        "mov dword ptr [ebp - 4], eax",
        "push esi",
        "push edi",
    ]
    assert _diff_and_match(orig_asm, recomp_asm) is True


def test_relocate_rejects_move_across_call():
    """A call is a barrier: memory and registers may change."""
    orig_asm = [
        "mov eax, dword ptr [g_state (DATA)]",
        "call <OFFSET1>",
        "push eax",
        "push esi",
    ]
    recomp_asm = [
        "call <OFFSET1>",
        "mov eax, dword ptr [g_state (DATA)]",
        "push eax",
        "push esi",
    ]
    assert _diff_and_match(orig_asm, recomp_asm) is False


def test_relocate_rejects_flags_consumed_after_move():
    """Both the moved instruction and a crossed instruction write flags,
    and a jump reads them afterward: the move changes the branch."""
    orig_asm = [
        "cmp eax, 1",
        "add ecx, 2",
        "je 0x8",
        "push esi",
    ]
    recomp_asm = [
        "add ecx, 2",
        "cmp eax, 1",
        "je 0x8",
        "push esi",
    ]
    assert _diff_and_match(orig_asm, recomp_asm) is False


def test_relocate_rejects_x87_reorder():
    """x87 instructions depend on the fp stack order: fadd and fmul on
    st(0) do not commute with each other."""
    orig_asm = [
        "fadd dword ptr [g_floatA (DATA)]",
        "fmul dword ptr [g_floatB (DATA)]",
        "pop esi",
        "pop edi",
    ]
    recomp_asm = [
        "fmul dword ptr [g_floatB (DATA)]",
        "fadd dword ptr [g_floatA (DATA)]",
        "pop esi",
        "pop edi",
    ]
    assert _diff_and_match(orig_asm, recomp_asm) is False
