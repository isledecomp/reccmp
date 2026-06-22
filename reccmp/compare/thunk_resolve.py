"""Resolve vtable slot targets through ILT thunks and raw mid-.text E9 jmp chains."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from reccmp.formats import Image
from reccmp.types import EntityType, ImageId

if TYPE_CHECKING:
    from reccmp.compare.db import EntityDb, ReccmpEntity

_MAX_HOPS = 8


def read_e9_jmp_target(binfile: Image, addr: int) -> int | None:
    """If *addr* begins a 5-byte ``jmp rel32`` (0xE9), return the jump target."""
    try:
        data = binfile.read(addr, 5)
    except Exception:
        return None
    if len(data) < 5 or data[0] != 0xE9:
        return None
    (operand,) = struct.unpack("<i", data[1:5])
    return addr + 5 + operand


def is_plausible_vtable_target(binfile: Image, addr: int) -> bool:
    """Heuristic: vtable slots point at code or ILT thunks, not RTTI/strings."""
    if addr == 0:
        return True
    if addr < 0x10000:
        return False
    try:
        data = binfile.read(addr, 1)
    except Exception:
        return False
    if not data:
        return False
    # Executable mapping or incremental-link stub opcode.
    return data[0] in (0xE9, 0x55, 0x6A, 0x83, 0x8B, 0xC3, 0x33, 0x56, 0x57, 0x51, 0x53)


def effective_orig_vtable_size(
    binfile: Image, orig_addr: int, read_size: int
) -> int:
    """Trim comparison past the last plausible orig vtable slot.

    Recompiled vtables are often longer than the original (extra inherited tail).
    Reading ``recomp_size`` bytes from the orig address pulls in the next object in
    ``.rdata`` and tanks the match ratio (TMapMaker is the canonical case).
    """
    if read_size <= 0 or read_size % 4 != 0:
        return read_size

    try:
        table = binfile.read(orig_addr, read_size)
    except Exception:
        return read_size

    last_nonzero_code = -1
    for i, (slot,) in enumerate(struct.iter_unpack("<L", table)):
        if slot != 0 and is_plausible_vtable_target(binfile, slot):
            last_nonzero_code = i

    if last_nonzero_code < 0:
        return read_size

    return (last_nonzero_code + 1) * 4


def resolve_vtable_slot(
    db: EntityDb,
    image_id: ImageId,
    binfile: Image,
    raw_addr: int,
    *,
    max_hops: int = _MAX_HOPS,
) -> ReccmpEntity | None:
    """Follow thunk DB entries and raw single-flow JMP stubs to a paired FUNCTION.

    MSVC incremental-link tables (ILT) at the start of ``.text`` are modeled as
    ``EntityType.THUNK`` with a single ``ref_*`` hop. Some vtable slots point at
    bad ILT aliases that forward through an unregistered mid-``.text`` ``E9`` stub
    before reaching a second ILT entry and the real body. Mirrors
    ``tools/ghidra/vtable_slots.py`` ``resolve()`` in the Imperialism decomp.
    """
    ref_key = "ref_orig" if image_id == ImageId.ORIG else "ref_recomp"
    addr = raw_addr
    last_entity: ReccmpEntity | None = None

    for _ in range(max_hops):
        entity = db.get(image_id, addr, exact=True)
        if entity is not None:
            last_entity = entity
            if entity.entity_type == EntityType.FUNCTION:
                return entity
            if entity.entity_type == EntityType.THUNK:
                ref_addr = entity.get(ref_key)
                if isinstance(ref_addr, int):
                    target = db.get(image_id, ref_addr, exact=True)
                    if (
                        target is not None
                        and target.entity_type == EntityType.FUNCTION
                    ):
                        return target
                    addr = ref_addr
                    continue

        next_addr = read_e9_jmp_target(binfile, addr)
        if next_addr is None or next_addr == addr:
            break
        addr = next_addr

    return last_entity
