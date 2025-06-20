"""Tests for asm sanitize, 32-bit pointers."""

from unittest.mock import Mock, patch
import pytest
from reccmp.isledecomp.compare.asm.parse import DisasmLiteInst, ParseAsm
from reccmp.isledecomp.compare.asm.replacement import (
    AddrTestProtocol,
    NameReplacementProtocol,
)


REGISTER_ONLY_INSTRUCTIONS = (
    # No operands
    DisasmLiteInst(0x1000, 1, "sti", ""),
    DisasmLiteInst(0x1000, 1, "ret", ""),
    # One operand
    DisasmLiteInst(0x1000, 1, "push", "eax"),
    DisasmLiteInst(0x1000, 2, "call", "eax"),
    # Two operands
    DisasmLiteInst(0x1000, 2, "cmp", "eax, edx"),
)


@pytest.mark.parametrize("inst", REGISTER_ONLY_INSTRUCTIONS)
def test_nothing_to_replace(inst: DisasmLiteInst):
    """There's no pointer or address value in these instructions,
    so your operand string should not be manipulated."""
    p = ParseAsm()
    (_, op_str) = p.sanitize(inst)
    assert op_str == inst.op_str


# There is one pointer in these instructions and we always replace it.
POINTER_INSTRUCTIONS = (
    # One operand
    DisasmLiteInst(0x1000, 6, "inc", "byte ptr [0x1234]"),
    DisasmLiteInst(0x1000, 6, "inc", "word ptr [0x1234]"),
    DisasmLiteInst(0x1000, 6, "inc", "dword ptr [0x1234]"),
    DisasmLiteInst(0x1000, 6, "inc", "qword ptr [0x1234]"),
    # Two operands
    DisasmLiteInst(0x1000, 5, "mov", "eax, dword ptr [0x1234]"),
    DisasmLiteInst(0x1000, 5, "mov", "dword ptr [0x1234], eax"),
)


@pytest.mark.parametrize("inst", POINTER_INSTRUCTIONS)
def test_pointer_instructions(inst: DisasmLiteInst):
    """Can identify the pointer and insert a placeholder, regardless of the size
    of the pointed-at-item or the operand position."""
    addr_test = Mock(spec=AddrTestProtocol, return_value=False)
    p = ParseAsm(addr_test=addr_test)
    (_, op_str) = p.sanitize(inst)

    # We always replace pointers. No need to verify the address.
    addr_test.assert_not_called()
    assert "[0x1234]" not in op_str
    assert "[<OFFSET1>]" in op_str


@pytest.mark.parametrize("inst", POINTER_INSTRUCTIONS)
def test_pointer_instructions_deterministic(inst: DisasmLiteInst):
    """Calling sanitize() twice on the same instruction should give the same result.
    i.e. we use the same placeholder for the same address."""
    p = ParseAsm()
    (_, op_str1) = p.sanitize(inst)
    (_, op_str2) = p.sanitize(inst)
    assert op_str1 == op_str2


@pytest.mark.parametrize("inst", POINTER_INSTRUCTIONS)
def test_pointer_instructions_with_name(inst: DisasmLiteInst):
    """Same as above, but using name lookup and substitution."""
    name_lookup = Mock(spec=NameReplacementProtocol, return_value="Hello")
    p = ParseAsm(name_lookup=name_lookup)
    (_, op_str) = p.sanitize(inst)

    # Using sample instructions where exact match is not required
    name_lookup.assert_called_with(0x1234, exact=False, indirect=False)
    assert "[0x1234]" not in op_str
    assert "[Hello]" in op_str


DISPLACE_INSTRUCTIONS = (
    # One operand
    DisasmLiteInst(0x1000, 6, "inc", "byte ptr [eax + 0x1234]"),
    # Two operands
    DisasmLiteInst(0x1000, 6, "mov", "eax, dword ptr [ecx + 0x1234]"),
    DisasmLiteInst(0x1000, 6, "mov", "dword ptr [ecx + 0x1234], eax"),
    DisasmLiteInst(0x1000, 7, "mov", "dword ptr [eax*4 + 0x1234], esi"),
    DisasmLiteInst(0x1000, 7, "mov", "esi, dword ptr [eax*4 + 0x1234]"),
    # Jump table
    DisasmLiteInst(0x1000, 7, "jmp", "dword ptr [eax*4 + 0x1234]"),
)


@pytest.mark.parametrize("inst", DISPLACE_INSTRUCTIONS)
def test_displacement_without_addr_verify(inst: DisasmLiteInst):
    """Can identify displacement operand (i.e. register plus address)
    but we only replace the value if it passes the address test."""
    p = ParseAsm()
    (_, op_str) = p.sanitize(inst)
    # No address test function provided, should not replace.
    assert op_str == inst.op_str


@pytest.mark.parametrize("inst", DISPLACE_INSTRUCTIONS)
def test_displacement_with_addr_verify(inst: DisasmLiteInst):
    """Same test as above, but with the address test function provided."""
    addr_test = Mock(spec=AddrTestProtocol, return_value=True)
    p = ParseAsm(addr_test=addr_test)
    (_, op_str) = p.sanitize(inst)

    addr_test.assert_called_with(0x1234)
    assert "0x1234]" not in op_str
    assert "<OFFSET1>]" in op_str


IMMEDIATE_VALUE_INSTRUCTIONS = (
    # One operand
    DisasmLiteInst(0x1000, 5, "push", "0x1234"),
    # Two operands
    DisasmLiteInst(0x1000, 5, "mov", "eax, 0x1234"),
)


@pytest.mark.parametrize("inst", IMMEDIATE_VALUE_INSTRUCTIONS)
def test_immediate_without_addr_verify(inst: DisasmLiteInst):
    """If an operand is just a number, we will substitute the name
    or placeholder if it passes the address test."""
    p = ParseAsm()
    (_, op_str) = p.sanitize(inst)
    # No address test function provided, should not replace.
    assert op_str == inst.op_str


@pytest.mark.parametrize("inst", IMMEDIATE_VALUE_INSTRUCTIONS)
def test_immediate_with_addr_verify(inst: DisasmLiteInst):
    """Same test as above, but with the address test function provided."""
    addr_test = Mock(spec=AddrTestProtocol, return_value=True)
    p = ParseAsm(addr_test=addr_test)
    (_, op_str) = p.sanitize(inst)

    addr_test.assert_called_with(0x1234)
    assert "0x1234" not in op_str
    assert "<OFFSET1>" in op_str


def test_pointer_and_immediate_is_not_addr():
    """Can handle instructions where two replacements are possible.
    In this case, we assume 0x5555 is not an address"""
    addr_test = Mock(spec=AddrTestProtocol, return_value=False)
    p = ParseAsm(addr_test=addr_test)
    inst = DisasmLiteInst(0x1000, 10, "mov", "dword ptr [0x1234], 0x5555")

    (_, op_str) = p.sanitize(inst)

    # We only verify the immediate address
    addr_test.assert_called_once()
    addr_test.assert_called_with(0x5555)

    # Assumes 0x5555 is not an address. Don't replace it.
    assert op_str == "dword ptr [<OFFSET1>], 0x5555"


def test_pointer_and_immediate_is_addr():
    """Same test as above, assumes 0x5555 is a valid address."""
    addr_test = Mock(spec=AddrTestProtocol, return_value=True)
    p = ParseAsm(addr_test=addr_test)
    inst = DisasmLiteInst(0x1000, 10, "mov", "dword ptr [0x1234], 0x5555")

    (_, op_str) = p.sanitize(inst)
    assert op_str == "dword ptr [<OFFSET1>], <OFFSET2>"


JUMP_SAMPLES = (
    (DisasmLiteInst(0x1000, 5, "jmp", "0x10ac"), "0xa7"),
    (DisasmLiteInst(0x1000, 5, "jmp", "0x805"), "-0x800"),
    (DisasmLiteInst(0x1000, 2, "je", "0x1006"), "0x4"),
    (DisasmLiteInst(0x1000, 2, "je", "0x1000"), "-0x2"),
)


@pytest.mark.parametrize("inst, expected", JUMP_SAMPLES)
def test_jump_displacement(inst: DisasmLiteInst, expected: str):
    """Jump instructions use a displacement value as their operand.
    Meaning: the jump destination is the jump instruction's address
    plus the instruction size plus the operand value.
    capstone calculates the absolute address, but it is more helpful to the
    reader to see the raw displacement so you know whether the jump is up or down."""
    p = ParseAsm()
    (_, op_str) = p.sanitize(inst)
    assert op_str == expected


SMALL_INSTRUCTIONS = (
    b"\xfb",  # sti
    b"\x53",  # push ebx
    b"\xc3",  # ret
    b"\xc2\x04\x00",  # ret 0x4
    b"\x66\x3d\x00\x01",  # cmp ax, 0x100
)


@pytest.mark.parametrize("code", SMALL_INSTRUCTIONS)
def test_skip_small_instructions(code: bytes):
    """One of our optimizations is to skip small (in bytes) instructions that
    we know could not contain an address.
    For 32-bit PE binaries, the starting virtual address is either 0x10000000
    or 0x4000000, so the instruction must be at least 5 bytes.
    (1 for the opcode, 4 for the operand)"""
    with patch("reccmp.isledecomp.compare.asm.parse.ParseAsm.sanitize") as mock:
        p = ParseAsm()
        p.parse_asm(code)
        mock.assert_not_called()


@pytest.mark.xfail(reason="Known issue.")
def test_should_skip_regardless_of_register():
    """Known limitation of the above optimization: using a different register
    changes the size of the instruction. Ideally we are consistent."""
    with patch("reccmp.isledecomp.compare.asm.parse.ParseAsm.sanitize") as mock:
        p = ParseAsm()
        p.parse_asm(b"\x66\x3d\x00\x01")  # cmp ax, 0x100
        p.parse_asm(b"\x66\x81\xf9\x00\x01")  # cmp cx, 0x100
        mock.assert_not_called()


def test_no_placeholder_for_jumps():
    """Some JMP instructions point at the start of another function (e.g. destructors
    called in the SEH Unwind section.) These would be candidates for a placeholder
    but doing this would cause the placeholder number to vary with annotation
    coverage. The compromise is to use the name if we have it, but not use a
    placeholder OR bump the placeholder number."""
    p = ParseAsm()
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "jmp", "0x2000"))

    # We don't have the name, so don't use a placeholder.
    assert op_str != "<OFFSET1>"


def test_jmp_ignore_placeholder():
    """Do not use a cached placeholder value for a JMP instruction."""
    p = ParseAsm()

    # Establish placeholder for 0x2000
    p.sanitize(DisasmLiteInst(0x1000, 5, "call", "0x2000"))
    assert 0x2000 in p.replacements

    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "jmp", "0x2000"))

    # Do not use the existing placeholder
    assert op_str != "<OFFSET1>"


def test_jmp_with_name_lookup():
    """Exact match required for JMP destination. This should be either the start of
    a function or an asm label"""
    name_lookup = Mock(spec=NameReplacementProtocol, return_value="Hello")
    p = ParseAsm(name_lookup=name_lookup)

    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "jmp", "0x2000"))

    name_lookup.assert_called_with(0x2000, exact=True, indirect=False)
    assert op_str == "Hello"


def test_cmp_without_name_lookup():
    """We intentionally do not use a placeholder for CMP instructions with an immediate value
    because it can hide a diff. Loops on an array of structs can use an arbitrary address
    past the end of the array for the range check. We want to see when this happens
    because it suggests that some variables are out of order."""
    addr_test = Mock(spec=AddrTestProtocol, return_value=False)
    p = ParseAsm(addr_test=addr_test)
    inst = DisasmLiteInst(0x1000, 5, "cmp", "eax, 0x2000")

    (_, op_str) = p.sanitize(inst)

    addr_test.assert_not_called()
    assert op_str == inst.op_str


def test_cmp_ignore_placeholder():
    """Do not use a cached placeholder value for an address in a CMP instruction.
    Always call the name lookup function."""
    p = ParseAsm()

    # Establish placeholder for 0x2000
    p.sanitize(DisasmLiteInst(0x1000, 5, "call", "0x2000"))
    assert 0x2000 in p.replacements

    inst = DisasmLiteInst(0x1000, 5, "cmp", "eax, 0x2000")

    (_, op_str) = p.sanitize(inst)

    # Do not use the existing placeholder
    assert op_str == inst.op_str


def test_cmp_with_name_lookup():
    """We will replace the value in a CMP instruction if we have a name for the address."""
    name_lookup = Mock(spec=NameReplacementProtocol, return_value="Hello")
    p = ParseAsm(name_lookup=name_lookup)
    inst = DisasmLiteInst(0x1000, 5, "cmp", "eax, 0x2000")

    (_, op_str) = p.sanitize(inst)

    name_lookup.assert_called_with(0x2000, exact=False, indirect=False)
    assert op_str == "eax, Hello"


def test_call_without_name_lookup():
    """CALL 0x____ instructions always use a placeholder."""
    addr_test = Mock(spec=AddrTestProtocol, return_value=False)
    p = ParseAsm(addr_test=addr_test)
    inst = DisasmLiteInst(0x1000, 5, "call", "0x1234")

    (_, op_str) = p.sanitize(inst)

    # Always replaced. Do not verify address.
    addr_test.assert_not_called()
    assert op_str == "<OFFSET1>"


def test_call_with_name_lookup():
    """CALL instructions require exact addr match"""
    name_lookup = Mock(spec=NameReplacementProtocol, return_value="Hello")
    p = ParseAsm(name_lookup=name_lookup)
    inst = DisasmLiteInst(0x1000, 5, "call", "0x1234")

    (_, op_str) = p.sanitize(inst)

    name_lookup.assert_called_with(0x1234, exact=True, indirect=False)
    assert op_str == "Hello"


def test_replacement_numbering():
    """If we can use the name lookup for the first address but not the second,
    the second replacement should be <OFFSET2> not <OFFSET1>."""

    def substitute_1234(addr: int, **_) -> str | None:
        return "Hello" if addr == 0x1234 else None

    substitute_1234_mock = Mock(side_effect=substitute_1234)

    p = ParseAsm(name_lookup=substitute_1234_mock)

    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 6, "inc", "dword ptr [0x1234]"))
    assert op_str == "dword ptr [Hello]"

    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 6, "inc", "dword ptr [0x5555]"))
    assert op_str == "dword ptr [<OFFSET2>]"


def test_absolute_indirect():
    """Read the given pointer and replace its value with a name or placeholder.
    Previously we handled reading from the binary inside the sanitize function.
    This is now delegated to the name lookup function, so we just need to check
    that it was called with the indirect parameter set."""
    name_lookup = Mock(spec=NameReplacementProtocol, return_value=None)
    p = ParseAsm(name_lookup=name_lookup)
    inst = DisasmLiteInst(0x1000, 5, "call", "dword ptr [0x1234]")

    (_, op_str) = p.sanitize(inst)

    name_lookup.assert_called_with(0x1234, exact=True, indirect=True)
    assert op_str == "dword ptr [<OFFSET1>]"


def test_direct_and_indirect_different_names():
    """Indirect pointers should not collide with
    cached lookups on direct pointers and vice versa"""

    # Create a lookup that checks indirect access
    def lookup(_, indirect: bool = False, **__) -> str:
        return "Indirect" if indirect else "Direct"

    lookup_mock = Mock(side_effect=lookup)

    indirect_inst = DisasmLiteInst(0x1000, 5, "call", "dword ptr [0x1234]")
    direct_inst = DisasmLiteInst(0x1000, 5, "mov", "eax, dword ptr [0x1234]")

    # Indirect first
    p = ParseAsm(name_lookup=lookup_mock)
    (_, op_str) = p.sanitize(indirect_inst)
    assert op_str == "dword ptr [Indirect]"

    (_, op_str) = p.sanitize(direct_inst)
    assert op_str == "eax, dword ptr [Direct]"

    # Direct first
    p = ParseAsm(name_lookup=lookup_mock)
    (_, op_str) = p.sanitize(direct_inst)
    assert op_str == "eax, dword ptr [Direct]"

    (_, op_str) = p.sanitize(indirect_inst)
    assert op_str == "dword ptr [Indirect]"

    # Now verify that we use cached values for each
    name_lookup = Mock(spec=NameReplacementProtocol, return_value=None)
    p.name_lookup = name_lookup
    (_, op_str) = p.sanitize(indirect_inst)
    assert op_str == "dword ptr [Indirect]"

    (_, op_str) = p.sanitize(direct_inst)
    assert op_str == "eax, dword ptr [Direct]"

    name_lookup.assert_not_called()


def test_direct_and_indirect_placeholders():
    """If no addresses are known, placeholders for direct and indirect lookup must be distinct"""
    indirect_inst = DisasmLiteInst(0x1000, 5, "call", "dword ptr [0x1234]")
    direct_inst = DisasmLiteInst(0x1000, 5, "mov", "eax, dword ptr [0x1234]")

    name_lookup = Mock(spec=NameReplacementProtocol, return_value=None)
    p = ParseAsm(name_lookup=name_lookup)

    (_, indirect_op_str) = p.sanitize(indirect_inst)
    (_, direct_op_str) = p.sanitize(direct_inst)

    # Must use two different placeholders
    assert indirect_op_str != direct_op_str


def test_consistent_numbering():
    """In previous versions of reccmp, offset number would vary
    depending on annotation coverage. The reason is that JMP destinations
    and CMP immediate values are set only if the name is known, and the
    placeholder offset number would increase when these were replaced.
    The number should be consistent regardless of whether we replace
    a value in these two kinds of instructions."""
    code = (
        b"\xe8\xfb\x0f\x00\x00"  #####  call  0x1000
        b"\xe9\xf6\x7f\x00\x00"  #####  jmp   0x8000
        b"\xa1\x34\x12\x00\x00"  #####  mov   eax, dword ptr [0x1234]
        b"\x3d\x55\x55\x00\x00"  #####  cmp   eax, 0x5555
        b"\xff\x05\x00\x20\x00\x00"  #  inc   dword ptr [0x2000]
    )

    # Run without name lookup
    p = ParseAsm()
    p.parse_asm(code)
    assert p.replacements[0x1000] == "<OFFSET1>"
    assert p.replacements[0x1234] == "<OFFSET2>"
    assert p.replacements[0x2000] == "<OFFSET3>"

    # Assume only the JMP and CMP addresses are known so we can test
    # the placeholder string for the other values.
    def name_lookup(addr: int, *_, **__) -> str | None:
        return {0x5555: "Test", 0x8000: "Hello"}.get(addr)

    # Must be empty before starting
    p = ParseAsm(name_lookup=name_lookup)
    assert len(p.replacements) == 0

    # Expect the two addresses to get the same placeholder
    p.parse_asm(code)
    assert p.replacements[0x1000] == "<OFFSET1>"
    assert p.replacements[0x1234] == "<OFFSET2>"
    assert p.replacements[0x2000] == "<OFFSET3>"
