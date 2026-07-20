"""Mutation tests for the effective-match verifier.

Every pair accepted as an effective match must stop being effective when
one semantic detail is changed: an immediate, a displacement, a global
symbol, a condition code, an operation, or a stored value. A mutation
that survives would mean the verifier is blind to that detail.

Register names are deliberately not mutated: renaming a register can be
a semantics-preserving change (that is the point of the verifier)."""

import difflib
import re

import pytest

from reccmp.compare.asm.effective import (
    CallAbi,
    FunctionMetadata,
    verify_effective_match,
)

CDECL = CallAbi(uses_ecx=False, uses_edx=False)

# (name, orig, recomp, metadata) — all accepted as effective matches.
ACCEPTED_PAIRS = [
    (
        "rename_store",
        [
            "mov eax, dword ptr [ebp - 4]",
            "add eax, 5",
            "mov dword ptr [esi + 8], eax",
        ],
        [
            "mov ecx, dword ptr [ebp - 4]",
            "add ecx, 5",
            "mov dword ptr [esi + 8], ecx",
        ],
        None,
    ),
    (
        "swapped_cmp",
        ["cmp eax, ecx", "jg 0x10", "mov dword ptr [esi], 1", "ret"],
        ["cmp ecx, eax", "jl 0x10", "mov dword ptr [esi], 1", "ret"],
        FunctionMetadata(return_kind="void"),
    ),
    (
        "commutative_add",
        [
            "mov eax, dword ptr [ebp - 4]",
            "add eax, dword ptr [ebp - 8]",
            "mov dword ptr [esi], eax",
        ],
        [
            "mov eax, dword ptr [ebp - 8]",
            "add eax, dword ptr [ebp - 4]",
            "mov dword ptr [esi], eax",
        ],
        None,
    ),
    (
        "x87_chain",
        [
            "mov eax, dword ptr [ecx + 0x94]",
            "movsx edx, word ptr [eax + 0xc]",
            "mov eax, dword ptr [ecx + 0x9c]",
            "fld dword ptr [edx*4 + g_tableA (DATA)]",
            "movsx ecx, word ptr [eax + 0xc]",
            "fadd dword ptr [ecx*4 + g_tableB (DATA)]",
            "ret",
        ],
        [
            "mov eax, dword ptr [ecx + 0x9c]",
            "movsx edx, word ptr [eax + 0xc]",
            "mov eax, dword ptr [ecx + 0x94]",
            "fld dword ptr [edx*4 + g_tableB (DATA)]",
            "movsx ecx, word ptr [eax + 0xc]",
            "fadd dword ptr [ecx*4 + g_tableA (DATA)]",
            "ret",
        ],
        None,
    ),
    (
        "frame_slot",
        [
            "mov dword ptr [ebp - 4], eax",
            "mov ecx, dword ptr [ebp - 4]",
            "push ecx",
            "call Helper (FUNCTION)",
        ],
        [
            "mov dword ptr [ebp - 8], eax",
            "mov ecx, dword ptr [ebp - 8]",
            "push ecx",
            "call Helper (FUNCTION)",
        ],
        FunctionMetadata(return_kind="void", call_abi={"Helper (FUNCTION)": CDECL}.get),
    ),
    (
        "callee_save_swap",
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
        None,
    ),
    (
        "void_return_rename",
        [
            "mov eax, dword ptr [g_pContext (DATA)]",
            "mov ecx, dword ptr [esp + 4]",
            "mov dword ptr [eax + 0x84], ecx",
            "ret",
        ],
        [
            "mov ecx, dword ptr [g_pContext (DATA)]",
            "mov eax, dword ptr [esp + 4]",
            "mov dword ptr [ecx + 0x84], eax",
            "ret",
        ],
        FunctionMetadata(return_kind="void"),
    ),
]

_HEX_OR_INT = re.compile(r"0x[0-9a-f]+|\b\d+\b")
_SYMBOL = re.compile(r"\bg_\w+")

_MNEMONIC_FLIPS = {
    "add": "sub",
    "fadd": "fsub",
    "jg": "jge",
    "jl": "jle",
    "je": "jne",
    "mov": "add",
}


def _mutations(asm: list[str]):
    """Yield (description, mutated copy) with exactly one semantic change."""
    for index, line in enumerate(asm):
        # Perturb each numeric literal (immediate or displacement).
        for m in _HEX_OR_INT.finditer(line):
            value = int(m.group(0), 0)
            mutated = line[: m.start()] + hex(value + 4) + line[m.end() :]
            yield (
                f"line {index}: {line!r} -> {mutated!r}",
                [*asm[:index], mutated, *asm[index + 1 :]],
            )
        # Rename each global symbol.
        for m in _SYMBOL.finditer(line):
            mutated = line[: m.start()] + m.group(0) + "X" + line[m.end() :]
            yield (
                f"line {index}: {line!r} -> {mutated!r}",
                [*asm[:index], mutated, *asm[index + 1 :]],
            )
        # Flip the mnemonic.
        mnemonic, sep, rest = line.partition(" ")
        flip = _MNEMONIC_FLIPS.get(mnemonic)
        if flip and sep:
            mutated = flip + " " + rest
            yield (
                f"line {index}: {line!r} -> {mutated!r}",
                [*asm[:index], mutated, *asm[index + 1 :]],
            )
        # Delete the line entirely.
        yield (f"line {index}: delete {line!r}", [*asm[:index], *asm[index + 1 :]])


@pytest.mark.parametrize(
    "name,orig,recomp,metadata", ACCEPTED_PAIRS, ids=[p[0] for p in ACCEPTED_PAIRS]
)
def test_pair_is_accepted(name, orig, recomp, metadata):
    assert verify_effective_match(orig, recomp, metadata=metadata) is True


@pytest.mark.parametrize(
    "name,orig,recomp,metadata", ACCEPTED_PAIRS, ids=[p[0] for p in ACCEPTED_PAIRS]
)
def test_mutations_of_recomp_reject(name, orig, recomp, metadata):
    survivors = []
    for description, mutated in _mutations(recomp):
        codes = difflib.SequenceMatcher(None, orig, mutated).get_opcodes()
        if verify_effective_match(orig, mutated, metadata=metadata) or (
            verify_effective_match(orig, mutated, codes, metadata=metadata)
        ):
            survivors.append(description)
    assert not survivors, "surviving mutations:\n" + "\n".join(survivors)


@pytest.mark.parametrize(
    "name,orig,recomp,metadata", ACCEPTED_PAIRS, ids=[p[0] for p in ACCEPTED_PAIRS]
)
def test_mutations_of_orig_reject(name, orig, recomp, metadata):
    survivors = []
    for description, mutated in _mutations(orig):
        codes = difflib.SequenceMatcher(None, mutated, recomp).get_opcodes()
        if verify_effective_match(mutated, recomp, metadata=metadata) or (
            verify_effective_match(mutated, recomp, codes, metadata=metadata)
        ):
            survivors.append(description)
    assert not survivors, "surviving mutations:\n" + "\n".join(survivors)
