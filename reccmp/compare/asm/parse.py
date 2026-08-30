"""Converts x86 machine code into text (i.e. assembly). The end goal is to
compare the code in the original and recomp binaries, using longest common
subsequence (LCS), i.e. difflib.SequenceMatcher.
The capstone library takes the raw bytes and gives us the mnemonic
and operand(s) for each instruction. We need to "sanitize" the text further
so that virtual addresses are replaced by symbol name or a generic
placeholder string."""

import re
from functools import cache
from typing import Mapping
from typing_extensions import Buffer
from .const import JUMP_MNEMONICS, SINGLE_OPERAND_INSTS
from .instgen import DisasmLiteTuple, InstructGen, SectionType
from .replacement import AddrTestProtocol, NameReplacementProtocol

AsmExcerpt = list[tuple[int | None, str]]

OpRecord = tuple[str, tuple[tuple[int, str, bool], ...]]
"""Record of the address operands in one sanitized instruction:
(final instruction text,
 ((operand address, replacement text, strict), ...)).
The replacement text is the exact string that was inserted into (or, for
an immediate that we chose not to replace, kept in) the instruction text.
strict is True for operands that can only refer to the exact start of an
entity: a call target or an indirect pointer slot. Used for cross-side
operand equivalence."""

SectionLayout = tuple[tuple[str, int, int], ...]
"""Shape of the disassembly: one (section type name, relative start, item
count) triple per section, with the start relative to the function start.
Two functions with the same code should produce the same layout."""

ptr_replace_regex = re.compile(r"(?<=\[)(0x[0-9a-f]+)(?=\])")

displace_replace_regex = re.compile(r"(?<= )(0x[0-9a-f]+)(?=\])")

# For matching an immediate value operand
immediate_replace_regex = re.compile(r"(?<=, )(0x[0-9a-f]+)")


@cache
def from_hex(string: str) -> int | None:
    try:
        return int(string, 16)
    except ValueError:
        pass

    return None


class ParseAsm:
    # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        addr_test: AddrTestProtocol | None = None,
        name_lookup: NameReplacementProtocol | None = None,
        is_32bit: bool = True,
    ) -> None:
        self.addr_test = addr_test
        self.name_lookup = name_lookup
        self.is_32bit = is_32bit

        self.replacements: dict[int, str] = {}
        self.indirect_replacements: dict[int, str] = {}
        self.number_placeholders = True

        # Address operands of each sanitized instruction from the last
        # parse_asm() call, keyed by instruction address.
        self.op_records: dict[int, OpRecord] = {}
        self._cur_ops: list[tuple[int, str, bool]] = []

        # Section layout and confirmed table locations (relative to the
        # function start) from the last parse_asm() call.
        self.last_layout: SectionLayout = ()
        self.last_tables: dict[int, SectionType] = {}

    def reset(self):
        self.replacements = {}
        self.indirect_replacements = {}
        self.op_records = {}
        self._cur_ops = []
        self.last_layout = ()
        self.last_tables = {}

    def is_addr(self, value: int) -> bool:
        """Wrapper for user-provided address test"""
        if callable(self.addr_test):
            return self.addr_test(value)

        return False

    def lookup(
        self, addr: int, exact: bool = False, indirect: bool = False
    ) -> str | None:
        """Wrapper for user-provided name lookup"""
        if callable(self.name_lookup):
            return self.name_lookup(addr, exact=exact, indirect=indirect)

        return None

    def _next_placeholder(self) -> str:
        """The placeholder number corresponds to the number of addresses we have
        already replaced. This is so the number will be consistent across the diff
        if we can replace some symbols with actual names in recomp but not orig."""
        number = len(self.replacements) + len(self.indirect_replacements) + 1
        return f"<OFFSET{number}>" if self.number_placeholders else "<OFFSET>"

    def _record_op(self, addr: int, text: str, strict: bool = False):
        """Note an address operand of the instruction being sanitized."""
        self._cur_ops.append((addr, text, strict))

    def replace(self, addr: int, exact: bool = False) -> str:
        """Provide a replacement name for the given address."""
        if addr in self.replacements:
            text = self.replacements[addr]
        elif (name := self.lookup(addr, exact=exact)) is not None:
            self.replacements[addr] = text = name
        else:
            text = self._next_placeholder()
            self.replacements[addr] = text

        self._record_op(addr, text, strict=exact)
        return text

    def indirect_replace(self, addr: int) -> str:
        if addr in self.indirect_replacements:
            text = self.indirect_replacements[addr]
        elif (name := self.lookup(addr, exact=True, indirect=True)) is not None:
            self.indirect_replacements[addr] = text = name
        else:
            text = self._next_placeholder()
            self.indirect_replacements[addr] = text

        self._record_op(addr, text, strict=True)
        return text

    def hex_replace_always(self, match: re.Match) -> str:
        """If a pointer value was matched, always insert a placeholder"""
        value = int(match.group(1), 16)
        return self.replace(value)

    def hex_replace_relocated(self, match: re.Match) -> str:
        """For replacing immediate value operands. We only want to
        use the placeholder if we are certain that this is a valid address.
        We can check the relocation table to find out."""
        value = int(match.group(1), 16)
        if self.is_addr(value):
            return self.replace(value)

        return match.group(0)

    def hex_replace_annotated(self, match: re.Match) -> str:
        """For replacing immediate value operands. Here we replace the value
        only if the name lookup returns something. Do not use a placeholder."""
        value = int(match.group(1), 16)
        placeholder = self.lookup(value)
        if placeholder is not None:
            self._record_op(value, placeholder)
            return placeholder

        # Even though we keep the raw value, record it as a potential
        # address operand so that cross-side refinement can still try to
        # match it up against the other side.
        self._record_op(value, match.group(0))
        return match.group(0)

    def hex_replace_indirect(self, match: re.Match) -> str:
        """Edge case for hex_replace_always. The context of the instruction
        tells us that the pointer value is an absolute indirect.
        So we go to that location in the binary to get the address.
        If we cannot identify the indirect address, fall back to a lookup
        on the original pointer value so we might display something useful."""
        value = int(match.group(1), 16)
        return self.indirect_replace(value)

    def sanitize(self, inst: DisasmLiteTuple) -> tuple[str, str]:
        # For jumps or calls, if the entire op_str is a hex number, the value
        # is a relative offset.
        # Otherwise (i.e. it looks like `dword ptr [address]`) it is an
        # absolute indirect that we will handle below.
        # Providing the starting address of the function to capstone.disasm has
        # automatically resolved relative offsets to an absolute address.
        # We will have to undo this for some of the jumps or they will not match.
        inst_address, inst_size, inst_mnemonic, inst_op_str = inst

        if (
            inst_mnemonic in SINGLE_OPERAND_INSTS
            and (op_str_address := from_hex(inst_op_str)) is not None
        ):
            if inst_mnemonic == "call":
                return (inst_mnemonic, self.replace(op_str_address, exact=True))

            if inst_mnemonic == "push":
                if self.is_addr(op_str_address):
                    return (inst_mnemonic, self.replace(op_str_address))

                # To avoid falling into jump handling
                return (inst_mnemonic, inst_op_str)

            if inst_mnemonic == "jmp":
                # The unwind section contains JMPs to other functions.
                # If we have a name for this address, use it. If not,
                # do not create a new placeholder. We will instead
                # fall through to generic jump handling below.
                potential_name = self.lookup(op_str_address, exact=True)
                if potential_name is not None:
                    return (inst_mnemonic, potential_name)

            # Else: this is any jump
            # Show the jump offset rather than the absolute address
            jump_displacement = op_str_address - (inst_address + inst_size)
            return (inst_mnemonic, hex(jump_displacement))

        if inst_mnemonic == "call":
            # Special handling for absolute indirect CALL.
            op_str = ptr_replace_regex.sub(self.hex_replace_indirect, inst_op_str)
        else:
            op_str = ptr_replace_regex.sub(self.hex_replace_always, inst_op_str)

            # We only want relocated addresses for pointer displacement.
            # i.e. ptr [register + something]
            # Otherwise we would use a placeholder for every stack variable,
            # vtable call, or this->member access.
            op_str = displace_replace_regex.sub(self.hex_replace_relocated, op_str)

        # In the event of pointer comparison, only replace the immediate value
        # if it is a known address.
        if inst_mnemonic == "cmp":
            op_str = immediate_replace_regex.sub(self.hex_replace_annotated, op_str)
        else:
            op_str = immediate_replace_regex.sub(self.hex_replace_relocated, op_str)

        return (inst_mnemonic, op_str)

    def parse_asm(
        self,
        data: Buffer,
        start_addr: int,
        table_seeds: Mapping[int, SectionType] | None = None,
    ) -> AsmExcerpt:
        """Disassemble and sanitize the given code.
        table_seeds provides known jump/data table locations, relative to
        start_addr, to guide the disassembly. (e.g. shared from the
        disassembly of the same function in the other image)"""
        self.reset()
        asm: AsmExcerpt = []

        seeds = (
            {start_addr + rel: type_ for rel, type_ in table_seeds.items()}
            if table_seeds is not None
            else None
        )
        ig = InstructGen(bytes(data), start_addr, self.is_32bit, seeds=seeds)

        for section in ig.sections:
            if section.type == SectionType.CODE:
                for inst in section.contents:
                    inst_address, inst_size, inst_mnemonic, inst_op_str = inst
                    # If there is no pointer or immediate value in the op_str,
                    # there is nothing to sanitize.
                    # This leaves us with cases where a small immediate value or
                    # small displacement (this.member or vtable calls) appears.
                    # If we assume that instructions we want to sanitize need to be 5
                    # bytes -- 1 for the opcode and 4 for the address -- exclude cases
                    # where the hex value could not be an address.
                    # The exception is jumps which are as small as 2 bytes
                    # but are still useful to sanitize.
                    if "0x" in inst_op_str and (
                        inst_mnemonic in JUMP_MNEMONICS
                        or inst_size > 4
                        or not self.is_32bit
                    ):
                        self._cur_ops = []
                        result = self.sanitize(inst)
                        if self._cur_ops:
                            self.op_records[inst_address] = (
                                " ".join(result),
                                tuple(self._cur_ops),
                            )
                    else:
                        result = (inst_mnemonic, inst_op_str)

                    # mnemonic + " " + op_str
                    asm.append((inst_address, " ".join(result)))
            elif section.type == SectionType.ADDR_TAB:
                asm.append((None, "Jump table:"))
                for ofs, target in section.contents:
                    # Jumps in jump tables are absolute, which can lead to false positives
                    # when the function does not have the same address in orig and recomp.
                    # Therefore, we compute where the jump will go relative to the start of the function.
                    target_relative_to_function_start = target - start_addr
                    asm.append(
                        (ofs, f"start + 0x{(target_relative_to_function_start):x}")
                    )

            elif section.type == SectionType.DATA_TAB:
                asm.append((None, "Data table:"))
                for ofs, b in section.contents:
                    asm.append((ofs, hex(b)))

        self.last_layout = tuple(
            (
                section.type.name,
                (section.contents[0][0] - start_addr) if section.contents else -1,
                len(section.contents),
            )
            for section in ig.sections
        )
        self.last_tables = {
            addr - start_addr: type_
            for addr, type_ in ig.confirmed_addrs.items()
            if type_ != SectionType.CODE
        }

        return asm
