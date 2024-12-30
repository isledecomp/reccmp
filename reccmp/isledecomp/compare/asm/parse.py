"""Converts x86 machine code into text (i.e. assembly). The end goal is to
compare the code in the original and recomp binaries, using longest common
subsequence (LCS), i.e. difflib.SequenceMatcher.
The capstone library takes the raw bytes and gives us the mnemonic
and operand(s) for each instruction. We need to "sanitize" the text further
so that virtual addresses are replaced by symbol name or a generic
placeholder string."""

import re
import struct
from functools import cache
from typing import Callable, List, Optional, Tuple
from collections import namedtuple
from .const import JUMP_MNEMONICS, SINGLE_OPERAND_INSTS
from .instgen import InstructGen, SectionType
from .replacement import AddrTestProtocol, NameReplacementProtocol

ptr_replace_regex = re.compile(r"\[(0x[0-9a-f]+)\]")

displace_replace_regex = re.compile(r"\+ (0x[0-9a-f]+)\]")

# For matching an immediate value on its own.
# Preceded by start-of-string (first operand) or comma-space (second operand)
immediate_replace_regex = re.compile(r"(?:^|, )(0x[0-9a-f]+)")

DisasmLiteInst = namedtuple("DisasmLiteInst", "address, size, mnemonic, op_str")


@cache
def from_hex(string: str) -> Optional[int]:
    try:
        return int(string, 16)
    except ValueError:
        pass

    return None


def bytes_to_dword(b: bytes) -> Optional[int]:
    if len(b) == 4:
        return struct.unpack("<L", b)[0]

    return None


class ParseAsm:
    def __init__(
        self,
        addr_test: Optional[AddrTestProtocol] = None,
        name_lookup: Optional[NameReplacementProtocol] = None,
        bin_lookup: Optional[Callable[[int, int], Optional[bytes]]] = None,
    ) -> None:
        self.addr_test = addr_test
        self.name_lookup = name_lookup
        self.bin_lookup = bin_lookup
        self.replacements = {}
        self.number_placeholders = True

    def reset(self):
        self.replacements = {}

    def is_addr(self, value: int) -> bool:
        """Wrapper for user-provided address test"""
        if callable(self.addr_test):
            return self.addr_test(value)

        return False

    def lookup(self, addr: int, exact: bool = False) -> Optional[str]:
        """Wrapper for user-provided name lookup"""
        if callable(self.name_lookup):
            return self.name_lookup(addr, exact=exact)

        return None

    def replace(self, value: int, exact: bool = False, test: bool = False) -> str:
        """Provide a replacement name for the given address."""
        if test and not self.is_addr(value):
            return hex(value)  # TODO.

        if value in self.replacements:
            return self.replacements[value]

        if (name := self.lookup(value, exact=exact)) is not None:
            self.replacements[value] = name
            return name

        # The placeholder number corresponds to the number of addresses we have
        # already replaced. This is so the number will be consistent across the diff
        # if we can replace some symbols with actual names in recomp but not orig.
        idx = len(self.replacements) + 1
        placeholder = f"<OFFSET{idx}>" if self.number_placeholders else "<OFFSET>"
        self.replacements[value] = placeholder
        return placeholder

    def hex_replace_always(self, match: re.Match) -> str:
        """If a pointer value was matched, always insert a placeholder"""
        value = int(match.group(1), 16)
        return match.group(0).replace(match.group(1), self.replace(value))

    def hex_replace_relocated(self, match: re.Match) -> str:
        """For replacing immediate value operands. We only want to
        use the placeholder if we are certain that this is a valid address.
        We can check the relocation table to find out."""
        value = int(match.group(1), 16)
        return match.group(0).replace(
            match.group(1), self.replace(value, exact=False, test=True)
        )

    def hex_replace_annotated(self, match: re.Match) -> str:
        """For replacing immediate value operands. Here we replace the value
        only if the name lookup returns something. Do not use a placeholder."""
        value = int(match.group(1), 16)
        placeholder = self.lookup(value)
        if placeholder is not None:
            return match.group(0).replace(match.group(1), placeholder)

        return match.group(0)

    def hex_replace_indirect(self, match: re.Match) -> str:
        """Edge case for hex_replace_always. The context of the instruction
        tells us that the pointer value is an absolute indirect.
        So we go to that location in the binary to get the address.
        If we cannot identify the indirect address, fall back to a lookup
        on the original pointer value so we might display something useful."""
        value = int(match.group(1), 16)
        indirect_value = None

        if callable(self.bin_lookup):
            indirect_value = self.bin_lookup(value, 4)

        if indirect_value is not None:
            indirect_addr = bytes_to_dword(indirect_value)
            if indirect_addr is not None and self.lookup(indirect_addr) is not None:
                return match.group(0).replace(
                    match.group(1), "->" + self.replace(indirect_addr)
                )

        return match.group(0).replace(match.group(1), self.replace(value))

    def sanitize(self, inst: DisasmLiteInst) -> Tuple[str, str]:
        # For jumps or calls, if the entire op_str is a hex number, the value
        # is a relative offset.
        # Otherwise (i.e. it looks like `dword ptr [address]`) it is an
        # absolute indirect that we will handle below.
        # Providing the starting address of the function to capstone.disasm has
        # automatically resolved relative offsets to an absolute address.
        # We will have to undo this for some of the jumps or they will not match.

        if (
            inst.mnemonic in SINGLE_OPERAND_INSTS
            and (op_str_address := from_hex(inst.op_str)) is not None
        ):
            if inst.mnemonic == "call":
                return (inst.mnemonic, self.replace(op_str_address, exact=True))

            if inst.mnemonic == "push":
                return (inst.mnemonic, self.replace(op_str_address, test=True))

            if inst.mnemonic == "jmp":
                # The unwind section contains JMPs to other functions.
                # If we have a name for this address, use it. If not,
                # do not create a new placeholder. We will instead
                # fall through to generic jump handling below.
                potential_name = self.lookup(op_str_address, exact=True)
                if potential_name is not None:
                    return (inst.mnemonic, potential_name)

            # Else: this is any jump
            # Show the jump offset rather than the absolute address
            jump_displacement = op_str_address - (inst.address + inst.size)
            return (inst.mnemonic, hex(jump_displacement))

        if inst.mnemonic == "call":
            # Special handling for absolute indirect CALL.
            op_str = ptr_replace_regex.sub(self.hex_replace_indirect, inst.op_str)
        else:
            op_str = ptr_replace_regex.sub(self.hex_replace_always, inst.op_str)

            # We only want relocated addresses for pointer displacement.
            # i.e. ptr [register + something]
            # Otherwise we would use a placeholder for every stack variable,
            # vtable call, or this->member access.
            op_str = displace_replace_regex.sub(self.hex_replace_relocated, op_str)

        # In the event of pointer comparison, only replace the immediate value
        # if it is a known address.
        if inst.mnemonic == "cmp":
            op_str = immediate_replace_regex.sub(self.hex_replace_annotated, op_str)
        else:
            op_str = immediate_replace_regex.sub(self.hex_replace_relocated, op_str)

        return (inst.mnemonic, op_str)

    def parse_asm(self, data: bytes, start_addr: Optional[int] = 0) -> List[str]:
        self.reset()
        asm = []

        ig = InstructGen(data, start_addr)

        for sect_type, sect_contents in ig.sections:
            if sect_type == SectionType.CODE:
                for inst in sect_contents:
                    # Use heuristics to disregard some differences that aren't representative
                    # of the accuracy of a function (e.g. global offsets)

                    # If there is no pointer or immediate value in the op_str,
                    # there is nothing to sanitize.
                    # This leaves us with cases where a small immediate value or
                    # small displacement (this.member or vtable calls) appears.
                    # If we assume that instructions we want to sanitize need to be 5
                    # bytes -- 1 for the opcode and 4 for the address -- exclude cases
                    # where the hex value could not be an address.
                    # The exception is jumps which are as small as 2 bytes
                    # but are still useful to sanitize.
                    if "0x" in inst.op_str and (
                        inst.mnemonic in JUMP_MNEMONICS or inst.size > 4
                    ):
                        result = self.sanitize(inst)
                    else:
                        result = (inst.mnemonic, inst.op_str)

                    # mnemonic + " " + op_str
                    asm.append((hex(inst.address), " ".join(result)))
            elif sect_type == SectionType.ADDR_TAB:
                asm.append(("", "Jump table:"))
                for i, (ofs, _) in enumerate(sect_contents):
                    asm.append((hex(ofs), f"Jump_dest_{i}"))

            elif sect_type == SectionType.DATA_TAB:
                asm.append(("", "Data table:"))
                for ofs, b in sect_contents:
                    asm.append((hex(ofs), hex(b)))

        return asm
