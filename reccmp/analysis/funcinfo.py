"""Parsing SEH (Structured Exception Handling) data.
https://www.openrce.org/articles/full_view/21"""

import re
import struct
from typing import Iterable, Iterator, NamedTuple
from typing_extensions import Buffer
from reccmp.formats import PEImage

# Magic strings:
# - 0x19930520: up to VC6
# - 0x19930521: VC7.x(2002-2003)
# - 0x19930522: VC8 (2005)
FUNCINFO_MAGIC_RE = re.compile(rb"\x20\x05\x93\x19", flags=re.S)


# Match `mov eax, ____` instructions followed by jmp opcode. `B8 .... E9`
MOV_EAX_RE = re.compile(rb"(?=\xb8(.{4})\xe9)", flags=re.S)

# VC5 exception-registration prologue: push -1; push <handler>.
EH_REGISTRATION_RE = re.compile(rb"\x6a\xff\x68(.{4})", flags=re.S)


class UnwindMapEntry(NamedTuple):
    target_state: int
    action_addr: int


class FuncInfo(NamedTuple):
    addr: int
    unwinds: tuple[UnwindMapEntry, ...]


def find_funcinfo_offsets_in_buffer(buf: Buffer) -> Iterator[int]:
    """Return offsets of the FuncInfo magic number."""
    for match in FUNCINFO_MAGIC_RE.finditer(buf):
        yield match.start()


def find_funcinfo_in_buffer(buf: Buffer, base_addr: int) -> Iterator[FuncInfo]:
    """Parse the FuncInfo struct and return its location."""
    for ofs in find_funcinfo_offsets_in_buffer(buf):
        # TODO: The structure may vary depending on the magic string.
        # We support format 19930520 to start.
        max_state, unwind_map_addr = struct.unpack_from("<4x2I", buf, offset=ofs)

        # Unwind offset is an absolute address.
        unwind_map_ofs = unwind_map_addr - base_addr
        unwinds = tuple(
            UnwindMapEntry(
                *struct.unpack_from("<iI", buf, offset=unwind_map_ofs + 8 * i)
            )
            for i in range(max_state)
        )

        yield FuncInfo(addr=base_addr + ofs, unwinds=unwinds)


def find_funcinfo(image: PEImage) -> Iterator[FuncInfo]:
    """Find all FuncInfo structs in the image."""
    for region in image.get_const_regions():
        yield from find_funcinfo_in_buffer(region.data, region.addr)


def find_mov_eax_jmp_in_buffer(
    buf: Buffer, base_addr: int = 0
) -> Iterator[tuple[int, bytes]]:
    """Return offsets in the buffer that match a `mov eax, ____` instruction followed by `jmp`."""
    for match in MOV_EAX_RE.finditer(buf):
        yield (base_addr + match.start(), match.group(1))


def find_eh_handlers(image: PEImage) -> Iterator[tuple[int, FuncInfo]]:
    """Find each SEH handler function and its associated FuncInfo struct."""

    # There can be multiple code and const data sections in a program.
    # I'm not sure how the pairing of those would work (or if we could recognize it)
    # so we begin by detecting all FuncInfo structs before searching for the handlers.
    all_funcinfo = list(find_funcinfo(image))

    # Convert the FuncInfo address back into the LE byte string so it's easier to match it.
    bytes_to_addr = {struct.pack("<I", f.addr): f for f in all_funcinfo}

    for region in image.get_code_regions():
        for handler_addr, funcinfo_bytes in find_mov_eax_jmp_in_buffer(
            region.data, region.addr
        ):
            # If the address in the MOV EAX is one of our FuncInfo addresses
            if (funcinfo := bytes_to_addr.get(funcinfo_bytes)) is not None:
                # Return the EH handler address and the referenced FuncInfo struct
                yield (handler_addr, funcinfo)


def find_function_eh_handlers(
    image: PEImage,
    functions: Iterable[tuple[int, int]],
    handler_addrs: set[int],
) -> Iterator[tuple[int, int]]:
    """Relate functions to handlers referenced by their VC5 EH prologue.

    Only mutually unique relationships are returned. This avoids assigning a shared or
    coincidental handler-shaped operand by address order.
    """
    owner_candidates: dict[int, set[int]] = {}
    handler_candidates: dict[int, set[int]] = {}

    for function_addr, function_size in functions:
        if function_size <= 0:
            continue

        # The registration record is emitted in the prologue. Limiting the search also
        # prevents handler-looking constants in the body from becoming ownership proof.
        body = image.read(function_addr, min(function_size, 64))
        for match in EH_REGISTRATION_RE.finditer(body):
            handler_addr = struct.unpack("<I", match.group(1))[0]
            if handler_addr not in handler_addrs:
                continue

            owner_candidates.setdefault(function_addr, set()).add(handler_addr)
            handler_candidates.setdefault(handler_addr, set()).add(function_addr)

    for function_addr, candidates in owner_candidates.items():
        if len(candidates) != 1:
            continue

        (handler_addr,) = candidates
        if handler_candidates[handler_addr] == {function_addr}:
            yield function_addr, handler_addr
