"""Tests for the relational effective-match verifier
(reccmp.compare.asm.effective.verify_effective_match)."""

from reccmp.compare.asm.effective import verify_effective_match

# --- Register renaming (positive) ------------------------------------------


def test_rename_simple_live_range():
    """The most common allocation difference: the same computation flows
    through a different register. The store proves equivalence."""
    orig = [
        "mov eax, dword ptr [ebp - 4]",
        "add eax, 5",
        "mov dword ptr [esi + 8], eax",
    ]
    recomp = [
        "mov ecx, dword ptr [ebp - 4]",
        "add ecx, 5",
        "mov dword ptr [esi + 8], ecx",
    ]
    assert verify_effective_match(orig, recomp) is True


def test_rename_multiple_live_ranges():
    """The same physical registers hold different values over successive
    live ranges, allocated differently on each side."""
    orig = [
        "mov eax, dword ptr [ebp - 4]",
        "mov dword ptr [esi], eax",
        "mov ecx, dword ptr [ebp - 8]",
        "mov dword ptr [edi], ecx",
        "mov eax, dword ptr [ebp - 0xc]",
        "mov dword ptr [esi + 4], eax",
    ]
    recomp = [
        "mov edx, dword ptr [ebp - 4]",
        "mov dword ptr [esi], edx",
        "mov eax, dword ptr [ebp - 8]",
        "mov dword ptr [edi], eax",
        "mov edx, dword ptr [ebp - 0xc]",
        "mov dword ptr [esi + 4], edx",
    ]
    assert verify_effective_match(orig, recomp) is True


def test_rename_through_push_call():
    """An argument computed in different registers and pushed for a call."""
    orig = [
        "mov eax, dword ptr [esi + 4]",
        "push eax",
        "call <OFFSET1>",
        "add esp, 4",
        "ret",
    ]
    recomp = [
        "mov ecx, dword ptr [esi + 4]",
        "push ecx",
        "call <OFFSET1>",
        "add esp, 4",
        "ret",
    ]
    assert verify_effective_match(orig, recomp) is True


def test_rename_in_memory_operand():
    """Renamed registers used as base and index of an address."""
    orig = [
        "mov eax, dword ptr [ebp - 4]",
        "mov ecx, dword ptr [g_table (DATA)]",
        "mov edx, dword ptr [ecx + eax*4]",
        "mov dword ptr [ebp - 8], edx",
    ]
    recomp = [
        "mov edx, dword ptr [ebp - 4]",
        "mov eax, dword ptr [g_table (DATA)]",
        "mov ecx, dword ptr [eax + edx*4]",
        "mov dword ptr [ebp - 8], ecx",
    ]
    assert verify_effective_match(orig, recomp) is True


def test_rename_loop_body():
    """A renamed counter surviving a compare and backward jump."""
    orig = [
        "xor eax, eax",
        "add eax, 1",
        "cmp eax, 0x10",
        "jl -0x5",
        "ret",
    ]
    recomp = [
        "xor ecx, ecx",
        "add ecx, 1",
        "cmp ecx, 0x10",
        "jl -0x5",
        "ret",
    ]
    assert verify_effective_match(orig, recomp) is True


# --- Register renaming (negative) ------------------------------------------


def test_reject_rename_with_different_constants():
    orig = ["mov eax, 5", "push eax", "call <OFFSET1>"]
    recomp = ["mov ecx, 6", "push ecx", "call <OFFSET1>"]
    assert verify_effective_match(orig, recomp) is False


def test_reject_rename_with_different_globals():
    orig = ["mov eax, dword ptr [g_first (DATA)]", "mov dword ptr [esi], eax"]
    recomp = ["mov ecx, dword ptr [g_second (DATA)]", "mov dword ptr [esi], ecx"]
    assert verify_effective_match(orig, recomp) is False


def test_reject_rename_with_different_member_offset():
    orig = ["mov eax, dword ptr [esi + 4]", "push eax"]
    recomp = ["mov ecx, dword ptr [esi + 8]", "push ecx"]
    assert verify_effective_match(orig, recomp) is False


def test_reject_register_value_overwritten_before_use():
    """Registers cannot be swapped per-line: after `mov eax, 0` and
    `mov ecx, 1`, storing through eax is not storing through ecx."""
    orig = ["mov eax, 0", "mov ecx, 1", "mov dword ptr [eax], 2"]
    recomp = ["mov eax, 0", "mov ecx, 1", "mov dword ptr [ecx], 2"]
    assert verify_effective_match(orig, recomp) is False


def test_reject_partial_register_difference():
    """al and ah are not interchangeable when the full register is stored."""
    orig = ["mov al, 1", "mov dword ptr [esi], eax"]
    recomp = ["mov ah, 1", "mov dword ptr [esi], eax"]
    assert verify_effective_match(orig, recomp) is False


def test_reject_different_call_target():
    orig = ["push esi", "call <OFFSET1>", "pop esi", "ret"]
    recomp = ["push esi", "call <OFFSET2>", "pop esi", "ret"]
    assert verify_effective_match(orig, recomp) is False


def test_reject_different_return_value():
    orig = ["mov eax, dword ptr [g_first (DATA)]", "ret"]
    recomp = ["mov eax, dword ptr [g_second (DATA)]", "ret"]
    assert verify_effective_match(orig, recomp) is False


def test_reject_different_stored_value():
    orig = ["mov eax, dword ptr [ebp - 4]", "mov dword ptr [esi], eax"]
    recomp = ["mov eax, dword ptr [ebp - 8]", "mov dword ptr [esi], eax"]
    assert verify_effective_match(orig, recomp) is False


# --- Condition normalization -----------------------------------------------


def test_swapped_cmp_inverted_jump():
    orig = ["cmp eax, ecx", "jg 0x10"]
    recomp = ["cmp ecx, eax", "jl 0x10"]
    assert verify_effective_match(orig, recomp) is True


def test_reject_swapped_cmp_same_jump():
    """cmp a,b / jg is NOT cmp b,a / jg."""
    orig = ["cmp eax, ecx", "jg 0x10"]
    recomp = ["cmp ecx, eax", "jg 0x10"]
    assert verify_effective_match(orig, recomp) is False


def test_swapped_cmp_with_rename():
    """Condition normalization composes with register renaming."""
    orig = [
        "mov eax, dword ptr [ebp - 4]",
        "cmp eax, dword ptr [ebp - 8]",
        "jge 0x10",
        "ret",
    ]
    recomp = [
        "mov ecx, dword ptr [ebp - 8]",
        "cmp ecx, dword ptr [ebp - 4]",
        "jle 0x10",
        "ret",
    ]
    assert verify_effective_match(orig, recomp) is True


def test_reject_flags_consumed_after_divergence():
    """A jump must not be excused when the two sides compare different
    values."""
    orig = ["cmp eax, 5", "je 0x10"]
    recomp = ["cmp ecx, 5", "je 0x10"]
    assert verify_effective_match(orig, recomp) is False


def test_reject_different_jump_displacement():
    orig = ["cmp eax, ecx", "je 0x10"]
    recomp = ["cmp eax, ecx", "je 0x20"]
    assert verify_effective_match(orig, recomp) is False


# --- Commutative operations ------------------------------------------------


def test_commutative_add_operand_swap():
    orig = [
        "mov eax, dword ptr [ebp - 4]",
        "add eax, dword ptr [ebp - 8]",
        "mov dword ptr [esi], eax",
    ]
    recomp = [
        "mov eax, dword ptr [ebp - 8]",
        "add eax, dword ptr [ebp - 4]",
        "mov dword ptr [esi], eax",
    ]
    assert verify_effective_match(orig, recomp) is True


def test_reject_noncommutative_sub_swap():
    orig = [
        "mov eax, dword ptr [ebp - 4]",
        "sub eax, dword ptr [ebp - 8]",
        "mov dword ptr [esi], eax",
    ]
    recomp = [
        "mov eax, dword ptr [ebp - 8]",
        "sub eax, dword ptr [ebp - 4]",
        "mov dword ptr [esi], eax",
    ]
    assert verify_effective_match(orig, recomp) is False


def test_commutative_x87_chain():
    """The Imperialism x87 operand-chain swap, proven by dataflow rather
    than by the whole-function text pattern."""
    orig = [
        "mov eax, dword ptr [ecx + 0x94]",
        "movsx edx, word ptr [eax + 0xc]",
        "mov eax, dword ptr [ecx + 0x9c]",
        "fld dword ptr [edx*4 + g_tableA (DATA)]",
        "movsx ecx, word ptr [eax + 0xc]",
        "fadd dword ptr [ecx*4 + g_tableB (DATA)]",
        "ret",
    ]
    recomp = [
        "mov eax, dword ptr [ecx + 0x9c]",
        "movsx edx, word ptr [eax + 0xc]",
        "mov eax, dword ptr [ecx + 0x94]",
        "fld dword ptr [edx*4 + g_tableB (DATA)]",
        "movsx ecx, word ptr [eax + 0xc]",
        "fadd dword ptr [ecx*4 + g_tableA (DATA)]",
        "ret",
    ]
    assert verify_effective_match(orig, recomp) is True


def test_reject_x87_fsub_chain_swap():
    orig = ["fld dword ptr [ebp - 4]", "fsub dword ptr [ebp - 8]", "ret"]
    recomp = ["fld dword ptr [ebp - 8]", "fsub dword ptr [ebp - 4]", "ret"]
    assert verify_effective_match(orig, recomp) is False


def test_reject_x87_swap_across_fsqrt():
    """cos-like unary op between load and add: fsqrt(a) + b != fsqrt(b) + a."""
    orig = [
        "fld dword ptr [g_floatA (DATA)]",
        "fsqrt",
        "fadd dword ptr [g_floatB (DATA)]",
        "ret",
    ]
    recomp = [
        "fld dword ptr [g_floatB (DATA)]",
        "fsqrt",
        "fadd dword ptr [g_floatA (DATA)]",
        "ret",
    ]
    assert verify_effective_match(orig, recomp) is False


# --- Memory and unsupported instructions -----------------------------------


def test_load_after_store_generation():
    """A store between two loads of the same address means the second load
    may see a different value; both sides load in the same order, so this
    still matches."""
    orig = [
        "mov eax, dword ptr [esi]",
        "mov dword ptr [esi], 5",
        "mov ecx, dword ptr [esi]",
        "push ecx",
        "push eax",
    ]
    recomp = [
        "mov edx, dword ptr [esi]",
        "mov dword ptr [esi], 5",
        "mov eax, dword ptr [esi]",
        "push eax",
        "push edx",
    ]
    assert verify_effective_match(orig, recomp) is True


def test_reject_load_reordered_across_store():
    """Pushing the pre-store value where the other side pushes the
    post-store value is a real difference."""
    orig = [
        "mov eax, dword ptr [esi]",
        "mov dword ptr [esi], 5",
        "push eax",
    ]
    recomp = [
        "mov dword ptr [esi], 5",
        "mov eax, dword ptr [esi]",
        "push eax",
    ]
    assert verify_effective_match(orig, recomp) is False


def test_unsupported_instruction_identical_and_synced():
    """An instruction outside the model is fine while both sides agree."""
    orig = ["mov eax, dword ptr [esi]", "push eax", "cpuid", "pop eax", "ret"]
    recomp = ["mov eax, dword ptr [esi]", "push eax", "cpuid", "pop eax", "ret"]
    assert verify_effective_match(orig, recomp) is True


def test_reject_unsupported_instruction_while_diverged():
    """An unmodeled instruction may read any register, so it cannot be
    stepped over while a rename is in flight."""
    orig = ["mov eax, dword ptr [esi]", "cpuid", "mov dword ptr [edi], eax"]
    recomp = ["mov ecx, dword ptr [esi]", "cpuid", "mov dword ptr [edi], ecx"]
    assert verify_effective_match(orig, recomp) is False


def test_reject_length_mismatch():
    orig = ["mov eax, 1", "push eax"]
    recomp = ["push 1"]
    assert verify_effective_match(orig, recomp) is False


def test_data_tables_must_match_exactly():
    orig = ["jmp dword ptr [eax*4 + <OFFSET1>]", "Jump table:", "start + 0x10"]
    recomp = ["jmp dword ptr [eax*4 + <OFFSET1>]", "Jump table:", "start + 0x14"]
    assert verify_effective_match(orig, recomp) is False


def test_identical_sequences_match():
    orig = [
        "push ebp",
        "mov ebp, esp",
        "mov eax, dword ptr [ebp + 8]",
        "pop ebp",
        "ret",
    ]
    assert verify_effective_match(orig, list(orig)) is True


def test_void_return_rename_consumed_by_store():
    """A void setter: the renamed registers hold different (dead) values at
    ret, but both were consumed by the matched store. (Imperialism 0x41b400)"""
    orig = [
        "mov eax, dword ptr [g_pContext (DATA)]",
        "mov ecx, dword ptr [esp + 4]",
        "mov dword ptr [eax + 0x84], ecx",
        "ret",
    ]
    recomp = [
        "mov ecx, dword ptr [g_pContext (DATA)]",
        "mov eax, dword ptr [esp + 4]",
        "mov dword ptr [ecx + 0x84], eax",
        "ret",
    ]
    assert verify_effective_match(orig, recomp) is True


def test_partial_register_return_with_dead_upper_bits():
    """A function returning a 16-bit value in ax: the upper bits of eax
    differ (stale movsx vs. arithmetic leftovers) but are dead.
    (Imperialism 0x5128f0)"""
    orig = [
        "sub eax, 6",
        "movsx eax, ax",
        "mov ax, word ptr [eax*2 + g_lookup (DATA)]",
        "ret",
    ]
    recomp = [
        "sub eax, 6",
        "movsx ecx, ax",
        "mov ax, word ptr [ecx*2 + g_lookup (DATA)]",
        "ret",
    ]
    assert verify_effective_match(orig, recomp) is True


# --- Phase 6: frame slots, callee-save substitution, length differences ----


def test_frame_slot_renaming():
    """The same local lives at a different ebp offset in each build."""
    orig = [
        "mov dword ptr [ebp - 4], eax",
        "mov ecx, dword ptr [ebp - 4]",
        "push ecx",
        "call <OFFSET1>",
    ]
    recomp = [
        "mov dword ptr [ebp - 8], eax",
        "mov ecx, dword ptr [ebp - 8]",
        "push ecx",
        "call <OFFSET1>",
    ]
    assert verify_effective_match(orig, recomp) is True


def test_frame_slot_renaming_rejects_overlap():
    """Renamed slots must not overlap: [ebp-6] and [ebp-4] dwords do."""
    orig = [
        "mov dword ptr [ebp - 8], eax",
        "mov dword ptr [ebp - 4], ecx",
        "mov edx, dword ptr [ebp - 8]",
        "push edx",
    ]
    recomp = [
        "mov dword ptr [ebp - 6], eax",
        "mov dword ptr [ebp - 4], ecx",
        "mov edx, dword ptr [ebp - 6]",
        "push edx",
    ]
    assert verify_effective_match(orig, recomp) is False


def test_frame_slot_read_first_not_renamed():
    """A local that is read before being written holds unknown data; two
    different offsets must not be treated as the same slot."""
    orig = ["mov eax, dword ptr [ebp - 4]", "push eax"]
    recomp = ["mov eax, dword ptr [ebp - 8]", "push eax"]
    assert verify_effective_match(orig, recomp) is False


def test_frame_slot_renaming_rejects_escaped_address():
    """Once a frame address escapes via lea, renaming is off."""
    orig = [
        "mov dword ptr [ebp - 4], eax",
        "lea ecx, [ebp - 4]",
        "push ecx",
        "call <OFFSET1>",
    ]
    recomp = [
        "mov dword ptr [ebp - 8], eax",
        "lea ecx, [ebp - 8]",
        "push ecx",
        "call <OFFSET1>",
    ]
    assert verify_effective_match(orig, recomp) is False


def test_callee_save_register_substitution():
    """One build preserves and uses esi where the other picked edi."""
    orig = [
        "push esi",
        "mov esi, ecx",
        "mov eax, dword ptr [esi + 4]",
        "pop esi",
        "ret",
    ]
    recomp = [
        "push edi",
        "mov edi, ecx",
        "mov eax, dword ptr [edi + 4]",
        "pop edi",
        "ret",
    ]
    assert verify_effective_match(orig, recomp) is True


def test_callee_save_substitution_requires_matching_pop():
    """push esi vs push edi as a call argument is a real difference:
    the caller-saved values differ and no balanced pop follows."""
    orig = ["push esi", "call <OFFSET1>", "ret"]
    recomp = ["push edi", "call <OFFSET1>", "ret"]
    assert verify_effective_match(orig, recomp) is False


def test_one_sided_redundant_copy():
    """The recomp emits an extra register-to-register copy: instruction
    counts differ, but the extra copy has no observable effect."""
    import difflib

    orig = [
        "mov eax, dword ptr [esi]",
        "push eax",
        "call <OFFSET1>",
        "ret",
    ]
    recomp = [
        "mov ecx, dword ptr [esi]",
        "mov eax, ecx",
        "push eax",
        "call <OFFSET1>",
        "ret",
    ]
    codes = difflib.SequenceMatcher(None, orig, recomp).get_opcodes()
    assert verify_effective_match(orig, recomp, codes) is True
    # Without the diff opcodes, unequal lengths cannot be aligned.
    assert verify_effective_match(orig, recomp) is False


def test_one_sided_store_rejected():
    """An unmatched instruction with an observable effect (a store) is a
    real difference."""
    import difflib

    orig = ["mov eax, dword ptr [esi]", "push eax"]
    recomp = [
        "mov eax, dword ptr [esi]",
        "mov dword ptr [edi], 0",
        "push eax",
    ]
    codes = difflib.SequenceMatcher(None, orig, recomp).get_opcodes()
    assert verify_effective_match(orig, recomp, codes) is False
