"""Find multiple-inheritance thunk (vtordisp) functions."""

import re
import struct
from typing import Iterator, NamedTuple
from reccmp.isledecomp.formats.pe import PEImage

# Each vtordisp function begins with `sub ecx, <byte>`
VTOR_START_RE = re.compile(rb"\x2b\x49")

# n.b. These regex strings all use positive lookahead to support overlapping matches.
# They could be used individually to check the entire code section, but it is faster to
# check only spots where we can find `2B 49`.

# vtordisp{byte, 0} -- 8 bytes
VTOR_RE = re.compile(rb"(?=\x2b\x49(.)\xe9(.{4}))", flags=re.S)

# vtordisp{byte, dword} -- 14 bytes
VTOR_ADD_RE = re.compile(rb"(?=\x2b\x49(.)\x81\xc1(.{4})\xe9(.{4}))", flags=re.S)

# vtordisp{byte, byte} - 11 bytes
VTOR_SUB_RE = re.compile(rb"(?=\x2b\x49(.)\x83\xe9(.)\xe9(.{4}))", flags=re.S)


class VtordispFunction(NamedTuple):
    addr: int
    displacement: tuple[int, int]
    func_addr: int
    size: int


def find_displacements(buf: bytes, base_addr: int = 0) -> Iterator[VtordispFunction]:
    for start_match in VTOR_START_RE.finditer(buf):
        start = start_match.start()

        # For each of these three kinds of vtordisp:
        # 1.  Read one or two displacement values
        # 2.  If there is a second displacement value, it is positive or negative
        #     based on whether ADD or SUB instruction is used
        # 3.  Correct the jump displacement for the size of the function so we get
        #     the address of the function being thunked.

        if (match := VTOR_RE.match(buf[start:])) is not None:
            (displace,) = struct.unpack("b", match.group(1))
            (jmp_ofs,) = struct.unpack("<i", match.group(2))

            addr = base_addr + start
            jmp_addr = addr + 8 + jmp_ofs

            yield VtordispFunction(addr, (displace, 0), jmp_addr, 8)

        elif (match := VTOR_ADD_RE.match(buf[start:])) is not None:
            (displace,) = struct.unpack("b", match.group(1))
            (displace2,) = struct.unpack("<i", match.group(2))
            (jmp_ofs,) = struct.unpack("<i", match.group(3))

            addr = base_addr + start
            jmp_addr = addr + 14 + jmp_ofs

            yield VtordispFunction(addr, (displace, 2**32 - displace2), jmp_addr, 14)

        elif (match := VTOR_SUB_RE.match(buf[start:])) is not None:
            (displace,) = struct.unpack("b", match.group(1))
            (displace2,) = struct.unpack("b", match.group(2))
            (jmp_ofs,) = struct.unpack("<i", match.group(3))

            addr = base_addr + start
            jmp_addr = addr + 11 + jmp_ofs

            yield VtordispFunction(addr, (displace, displace2), jmp_addr, 11)


def find_vtordisp(image: PEImage) -> Iterator[VtordispFunction]:
    # TODO: Should check all code sections.
    code_sections = (image.get_section_by_name(".text"),)

    for sect in code_sections:
        yield from find_displacements(sect.view, sect.virtual_address)
