import difflib
import pytest
from reccmp.isledecomp.compare.asm.fixes import find_effective_match


def test_fix_cmp_jmp():
    orig_asm = ["mov eax, 1", "mov ebx, 2", "cmp eax, ebx", "jg 0x1"]
    recomp_asm = ["mov eax, 1", "mov ebx, 2", "cmp ebx, eax", "jl 0x1"]

    diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
    is_effective = find_effective_match(diff.get_opcodes(), orig_asm, recomp_asm)

    assert is_effective is True


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


@pytest.mark.xfail
def test_this_should_not_be_marked_as_effective():

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
