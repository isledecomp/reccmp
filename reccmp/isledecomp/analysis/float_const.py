"""Analysis related to x86 floating point instructions.
All floating point instructions use two byte opcodes. The first byte is in the range D8 to DF.
The second indicates the operation and pointer or registers used.

We are interested in floating point constants, so we want to exclude instructions that:
- access the status register or environment (FLDCW, FLDENV)
- store a value (FST, FSTP)
- refer to integers (FI*)

Then filter on pointers into read-only sections.
"""
import re
import struct
from collections.abc import Buffer
from typing import Iterator, NamedTuple
from reccmp.isledecomp.formats import PEImage

SINGLE_PRECISION_OPCODES = frozenset(
    [
        (0xD8, 0x05),  # fadd
        (0xD8, 0x0D),  # fmul
        (0xD8, 0x15),  # fcom
        (0xD8, 0x1D),  # fcomp
        (0xD8, 0x25),  # fsub
        (0xD8, 0x2D),  # fsubr
        (0xD8, 0x35),  # fdiv
        (0xD8, 0x3D),  # fdivr
        (0xD9, 0x05),  # fld
    ]
)

DOUBLE_PRECISION_OPCODES = frozenset(
    [
        (0xDC, 0x05),  # fadd
        (0xDC, 0x0D),  # fmul
        (0xDC, 0x15),  # fcom
        (0xDC, 0x1D),  # fcomp
        (0xDC, 0x25),  # fsub
        (0xDC, 0x2D),  # fsubr
        (0xDC, 0x35),  # fdiv
        (0xDC, 0x3D),  # fdivr
        (0xDD, 0x05),  # fld
    ]
)

FLOAT_OPCODES = frozenset([*SINGLE_PRECISION_OPCODES, *DOUBLE_PRECISION_OPCODES])


# Match a superset of the floating point instructions above.
# Uses positive lookahead to support overlapping matches.
FLOAT_INSTRUCTION_RE = re.compile(
    rb"(?=([\xd8\xd9\xdc\xdd][\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}))", flags=re.S
)


class FloatInstruction(NamedTuple):
    # The address (or offset) of the instruction
    address: int
    # Two byte opcode of the instruction
    opcode: tuple[int, int]
    # The address used in the operand
    pointer: int


def find_float_instructions_in_buffer(
    buf: Buffer, base_addr: int = 0
) -> Iterator[FloatInstruction]:
    """Search the given binary blob for floating-point instructions that reference a pointer.
    If the base addr is given, add it to the offset of the instruction to get an absolute address.
    """
    for match in FLOAT_INSTRUCTION_RE.finditer(buf):
        inst = match.group(1)
        opcode = (inst[0], inst[1])

        if opcode in FLOAT_OPCODES:
            (pointer,) = struct.unpack("<I", inst[2:6])
            yield FloatInstruction(base_addr + match.start(), opcode, pointer)


class FloatConstant(NamedTuple):
    address: int
    size: int
    value: float


def find_float_consts(image: PEImage) -> Iterator[FloatConstant]:
    """Floating point instructions that refer to a memory address can
    point to constant values. Search the code sections to find FP
    instructions and check whether the pointer address refers to
    read-only data."""

    # Multiple instructions can refer to the same float.
    # Return each float only once from this function.
    seen = set()

    # TODO: Should check all code and const data sections.
    code_sections = (image.get_section_by_name(".text"),)
    const_sections = (image.get_section_by_name(".rdata"),)

    for sect in code_sections:
        for inst in find_float_instructions_in_buffer(sect.view, sect.virtual_address):
            if inst.pointer in seen:
                continue

            seen.add(inst.pointer)

            # Make sure that the address of the operand is a relocation.
            if inst.address + 2 not in image.relocations:
                continue

            # Ignore instructions that point to variables
            if any(
                const_sect.contains_vaddr(inst.pointer) for const_sect in const_sections
            ):
                if inst.opcode in SINGLE_PRECISION_OPCODES:
                    # dword ptr -- single precision
                    (float_value,) = struct.unpack("<f", image.read(inst.pointer, 4))
                    yield FloatConstant(inst.pointer, 4, float_value)

                elif inst.opcode in DOUBLE_PRECISION_OPCODES:
                    # qword ptr -- double precision
                    (float_value,) = struct.unpack("<d", image.read(inst.pointer, 8))
                    yield FloatConstant(inst.pointer, 8, float_value)
