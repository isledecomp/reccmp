import re
import struct
from typing import Iterator, NamedTuple
from reccmp.isledecomp.formats import PEImage


# Match 6 byte absolute jump instructions.
ABS_JUMP_RE = re.compile(rb"(?<=\xff\x25).{4}", flags=re.S)


class ImportThunk(NamedTuple):
    addr: int
    import_addr: int
    # The size of the JMP instruction for the thunk
    # (i.e. the size of the thunk function)
    size: int


def find_absolute_jumps_in_bytes(
    raw: bytes, base_addr: int = 0
) -> Iterator[tuple[int, int]]:
    """Search the given binary blob for 6-byte JMP instructions.
    Return the address/offset of the jump and its destination.
    If the base addr is given, add it to the offset of the instruction to get an absolute address.
    """
    for match in ABS_JUMP_RE.finditer(raw):
        (jmp_dest,) = struct.unpack("<I", match.group(0))
        yield (base_addr + match.start() - 2, jmp_dest)


def find_import_thunks(image: PEImage) -> Iterator[ImportThunk]:
    """Imported functions may generate a thunk function somewhere in the code section.
    These are 6-byte JMP instructions with absolute offset.
    The functions given may or may not be thunks. For example: MSVC  _getSystemCP function
    """

    import_addrs = set(imp.addr for imp in image.imports)
    if not import_addrs:
        return

    for region in image.get_code_regions():
        for addr, jmp_dest in find_absolute_jumps_in_bytes(region.data, region.addr):
            if addr + 2 not in image.relocations:
                continue

            if jmp_dest in import_addrs:
                yield ImportThunk(addr, jmp_dest, 6)
