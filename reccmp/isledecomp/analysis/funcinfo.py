"""Parsing SEH (Structured Exception Handling) data.
https://www.openrce.org/articles/full_view/21"""

import re
import struct
from typing import Iterator, NamedTuple
from reccmp.isledecomp.formats import PEImage


# Magic strings:
# - 0x19930520: up to VC6
# - 0x19930521: VC7.x(2002-2003)
# - 0x19930522: VC8 (2005)
FUNCINFO_MAGIC_RE = re.compile(rb"\x20\x05\x93\x19", flags=re.S)


# Match `mov eax, ____` instructions followed by jmp opcode. `B8 .... E9`
MOV_EAX_RE = re.compile(rb"(?=\xb8(.{4})\xe9)", flags=re.S)


class FuncInfo(NamedTuple):
    addr: int
    unwinds: list[tuple[int, int]]


def find_funcinfo_offsets_in_buffer(buf: bytes) -> Iterator[int]:
    """Return offsets of the FuncInfo magic number."""
    for match in FUNCINFO_MAGIC_RE.finditer(buf):
        yield match.start()


def find_funcinfo_in_buffer(buf: bytes, base_addr: int) -> Iterator[FuncInfo]:
    """Parse the FuncInfo struct and return its location."""
    for ofs in find_funcinfo_offsets_in_buffer(buf):
        # TODO: The structure may vary depending on the magic string.
        # We support format 19930520 to start.
        (n_unwind, unwind_addr) = struct.unpack_from("<4x2I", buf, offset=ofs)

        # Unwind offset is an absolute address.
        unwind_ofs = unwind_addr - base_addr
        unwinds = list(
            struct.unpack_from("<iI", buf, offset=unwind_ofs + 8 * i)
            for i in range(n_unwind)
        )

        yield FuncInfo(addr=base_addr + ofs, unwinds=unwinds)


def find_funcinfo(image: PEImage) -> Iterator[FuncInfo]:
    """Find all FuncInfo structs in the image."""
    for region in image.get_const_regions():
        yield from find_funcinfo_in_buffer(region.data, region.addr)


def find_eh_handlers(image: PEImage) -> Iterator[tuple[int, FuncInfo]]:
    """Find each SEH handler function and its associated FuncInfo struct."""

    # There can be multiple code and const data sections in a program.
    # I'm not sure how the pairing of those would work (or if we could recognize it)
    # so we begin by detecting all FuncInfo structs before searching for the handlers.
    all_funcinfo = list(find_funcinfo(image))

    # Convert the FuncInfo address back into the LE byte string so it's easier to match it.
    bytes_to_addr = {struct.pack("<I", f.addr): f for f in all_funcinfo}

    for region in image.get_code_regions():
        for match in MOV_EAX_RE.finditer(region.data):
            # If the address in the MOV EAX is one of our FuncInfo addresses
            if (funcinfo := bytes_to_addr.get(match.group(1))) is not None:
                # Return the EH handler address and the FuncInfo address used
                yield (region.addr + match.start(), funcinfo)
