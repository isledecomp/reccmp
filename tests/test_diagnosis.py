"""Structured semantic diagnosis and strategy-selection tests."""

from difflib import SequenceMatcher

from reccmp.compare.asm.effective import (
    CallAbi,
    FunctionMetadata,
    _diagnostic_summaries,
)
from reccmp.compare.asm.fixes import analyze_effective_match
from reccmp.compare.asm.instgen import InstructionMeta
from reccmp.compare.diagnosis import ComparisonAnalysis, ComparisonStatus


def analyze(orig, recomp, **kwargs):
    codes = SequenceMatcher(None, orig, recomp).get_opcodes()
    return analyze_effective_match(codes, orig, recomp, **kwargs)


def test_exact_result():
    result = analyze(["mov eax, ecx", "ret"], ["mov eax, ecx", "ret"])
    assert result.status == ComparisonStatus.EXACT


def test_register_allocation_reason():
    result = analyze(
        ["mov eax, dword ptr [ebp - 4]", "mov dword ptr [esi], eax"],
        ["mov ecx, dword ptr [ebp - 4]", "mov dword ptr [esi], ecx"],
    )
    assert result.effective_reasons == ("register_allocation",)


def test_frame_slot_layout_reason():
    result = analyze(
        ["mov dword ptr [ebp - 4], eax", "mov ecx, dword ptr [ebp - 4]"],
        ["mov dword ptr [ebp - 8], eax", "mov ecx, dword ptr [ebp - 8]"],
    )
    assert result.effective_reasons == ("frame_slot_layout",)


def test_callee_save_substitution_reason():
    result = analyze(
        [
            "push esi",
            "mov esi, ecx",
            "mov eax, dword ptr [esi + 4]",
            "pop esi",
            "ret",
        ],
        [
            "push edi",
            "mov edi, ecx",
            "mov eax, dword ptr [edi + 4]",
            "pop edi",
            "ret",
        ],
    )
    assert "callee_save_substitution" in result.effective_reasons


def test_instruction_reorder_reason():
    result = analyze(
        [
            "mov eax, dword ptr [ebp - 4]",
            "mov ecx, dword ptr [ebp - 8]",
            "push ecx",
            "push eax",
        ],
        [
            "mov ecx, dword ptr [ebp - 8]",
            "mov eax, dword ptr [ebp - 4]",
            "push ecx",
            "push eax",
        ],
    )
    assert "instruction_reorder" in result.effective_reasons


def test_commutative_order_reason():
    result = analyze(
        [
            "mov eax, dword ptr [g_a (DATA)]",
            "add eax, dword ptr [g_b (DATA)]",
            "mov dword ptr [esi], eax",
        ],
        [
            "mov eax, dword ptr [g_b (DATA)]",
            "add eax, dword ptr [g_a (DATA)]",
            "mov dword ptr [esi], eax",
        ],
    )
    assert result.effective_reasons == ("commutative_order",)


def test_associative_add_order_reason():
    result = analyze(
        [
            "mov eax, dword ptr [g_a (DATA)]",
            "add eax, dword ptr [g_b (DATA)]",
            "add eax, dword ptr [g_c (DATA)]",
            "ret",
        ],
        [
            "mov eax, dword ptr [g_a (DATA)]",
            "add eax, dword ptr [g_c (DATA)]",
            "add eax, dword ptr [g_b (DATA)]",
            "ret",
        ],
        metadata=FunctionMetadata(return_kind="i32"),
    )
    assert result.status == ComparisonStatus.EFFECTIVE
    assert result.effective_reasons == ("commutative_order",)


def test_commutative_address_term_order_reason():
    result = analyze(
        ["mov eax, dword ptr [eax + edx]", "ret"],
        ["mov eax, dword ptr [edx + eax]", "ret"],
    )
    assert result.effective_reasons == ("commutative_order",)


def test_condition_inversion_reason():
    result = analyze(
        ["cmp eax, ebx", "jg 0x2", "ret"],
        ["cmp ebx, eax", "jl 0x2", "ret"],
    )
    assert result.effective_reasons == ("condition_inversion",)


def test_dead_operation_reason_and_effective_precedence():
    result = analyze(
        ["mov eax, dword ptr [esi]", "mov dword ptr [edi], eax"],
        [
            "mov ecx, dword ptr [esi]",
            "mov eax, ecx",
            "mov dword ptr [edi], eax",
        ],
    )
    assert result.status == ComparisonStatus.EFFECTIVE
    assert "dead_operation" in result.effective_reasons


def test_padding_reason():
    result = analyze(["ret"], ["ret", "int3"])
    assert result.status == ComparisonStatus.EFFECTIVE
    assert result.effective_reasons == ("padding",)


def test_call_target_difference():
    result = analyze(["call TView::Refresh"], ["call TView::Update"])
    assert result.difference.kind == "call_target"
    assert result.difference.orig.facts["target_name"] == "TView::Refresh"


def test_thiscall_argument_difference():
    metadata = FunctionMetadata(
        return_kind="void",
        call_abi={"TView::Refresh": CallAbi(True, False)}.get,
    )
    result = analyze(
        [
            "mov ecx, dword ptr [g_pMainView (DATA)]",
            "call TView::Refresh",
            "ret",
        ],
        [
            "mov ecx, dword ptr [g_pTitleView (DATA)]",
            "call TView::Refresh",
            "ret",
        ],
        metadata=metadata,
    )
    assert result.difference.kind == "call_argument"
    assert result.difference.orig.facts["register"] == "ecx"
    assert result.difference.orig.facts["value"] == "load:g_pMainView"


def test_memory_address_difference_has_components():
    result = analyze(
        ["mov eax, dword ptr [esi + 0x98]", "ret"],
        ["mov eax, dword ptr [esi + 0x9c]", "ret"],
    )
    assert result.difference.kind == "memory_address"
    assert result.difference.orig.facts == {
        "base_register": "esi",
        "index_register": None,
        "scale": 1,
        "displacement": 0x98,
        "symbol": None,
    }


def test_memory_value_difference():
    result = analyze(
        ["mov dword ptr [esi], 1"],
        ["mov dword ptr [esi], 2"],
    )
    assert result.difference.kind == "memory_value"


def test_immediate_value_difference():
    result = analyze(
        ["mov eax, 4", "mov dword ptr [esi], eax"],
        ["mov eax, 5", "mov dword ptr [esi], eax"],
    )
    assert result.difference.kind == "immediate_value"
    assert result.difference.orig.facts["value"] == 4


def test_branch_condition_difference():
    result = analyze(
        ["cmp eax, ebx", "je 0x2", "ret"],
        ["cmp eax, ebx", "jne 0x2", "ret"],
    )
    assert result.difference.kind == "branch_condition"


def _jump_meta(address: int, target: int) -> InstructionMeta:
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


def test_branch_target_difference_uses_canonical_indices():
    orig = ["cmp eax, ebx", "je 0x2", "inc eax", "ret"]
    recomp = ["cmp eax, ebx", "je 0x4", "inc eax", "ret"]
    result = analyze(
        orig,
        recomp,
        orig_addrs=[0x1000, 0x1002, 0x1004, 0x1005],
        recomp_addrs=[0x2000, 0x2002, 0x2004, 0x2005],
        orig_meta=[None, _jump_meta(0x1002, 0x1005), None, None],
        recomp_meta=[None, _jump_meta(0x2002, 0x2004), None, None],
    )
    assert result.difference.kind == "branch_target"
    assert result.difference.orig.facts["target_instruction_index"] == 3
    assert result.difference.recomp.facts["target_instruction_index"] == 2


def test_typed_return_value_difference():
    result = analyze(
        ["mov eax, 1", "ret"],
        ["mov eax, 2", "ret"],
        metadata=FunctionMetadata(return_kind="i32"),
    )
    assert result.difference.kind == "return_value"


def test_preserved_state_difference():
    result = analyze(
        ["mov ebx, 1"],
        ["mov ebx, 2"],
        metadata=FunctionMetadata(return_kind="void"),
    )
    assert result.difference.kind == "preserved_state"
    assert result.difference.orig.facts["register"] == "b"


def test_symbol_resolution_difference():
    result = analyze(
        ["mov eax, g_a (DATA)", "ret"],
        ["mov eax, g_b (DATA)", "ret"],
    )
    assert result.difference.kind == "symbol_resolution"


def test_unsupported_instruction_is_inconclusive():
    result = analyze(["bswap eax", "ret"], ["bswap ecx", "ret"])
    assert result.status == ComparisonStatus.INCONCLUSIVE
    assert result.inconclusive_reason == "missing_metadata"


def test_reason_order_is_deterministic():
    result = ComparisonAnalysis.effective({"padding", "dead_operation"})
    assert result.effective_reasons == ("dead_operation", "padding")


def test_colliding_symbolic_summaries_are_disambiguated():
    orig, recomp = _diagnostic_summaries(("poison", 1), ("poison", 2))
    assert orig.startswith("poison#")
    assert recomp.startswith("poison#")
    assert orig != recomp
