import re
import struct
from collections.abc import Collection, Iterator
from typing import NamedTuple
from typing_extensions import Buffer
from reccmp.formats import PEImage

# Match 6 byte absolute jump instructions.
ABS_JUMP_RE = re.compile(rb"(?<=\xff\x25).{4}", flags=re.S)


class ImportThunk(NamedTuple):
    addr: int
    import_addr: int
    # The size of the JMP instruction for the thunk
    # (i.e. the size of the thunk function)
    size: int


def find_absolute_jumps_in_bytes(
    raw: Buffer, base_addr: int = 0
) -> Iterator[tuple[int, int]]:
    """Search the given binary blob for 6-byte JMP instructions.
    Return the address/offset of the jump and its destination.
    If the base addr is given, add it to the offset of the instruction to get an absolute address.
    """
    for match in ABS_JUMP_RE.finditer(raw):
        (jmp_dest,) = struct.unpack("<I", match.group(0))
        yield (base_addr + match.start() - 2, jmp_dest)


def find_import_thunks(
    image: PEImage, function_starts: Collection[int] = ()
) -> Iterator[ImportThunk]:
    """Find six-byte absolute jumps to known IAT entries.

    A base relocation on the absolute operand is the usual evidence that the jump is an
    import thunk. Fixed-base images can omit those relocations, so an exact function-start
    entity is accepted as equivalent boundary evidence. Requiring either form of evidence
    avoids treating an absolute import tail-jump inside a larger source function as a thunk.
    """

    import_addrs = {imp.addr for imp in image.imports}
    if not import_addrs:
        return

    for region in image.get_code_regions():
        for addr, jmp_dest in find_absolute_jumps_in_bytes(region.data, region.addr):
            if jmp_dest not in import_addrs:
                continue

            if addr + 2 not in image.relocations and addr not in function_starts:
                continue

            yield ImportThunk(addr, jmp_dest, 6)
