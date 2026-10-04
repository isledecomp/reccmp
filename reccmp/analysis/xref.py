import enum
import re
from collections import Counter
from functools import partial
from typing import Callable, Mapping
from typing_extensions import Buffer
from reccmp.compare.asm.const import JUMP_MNEMONICS
from reccmp.compare.asm.instgen import (
    InstructGen,
    SectionType,
)
from reccmp.formats import Image
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb


class RefType(enum.Enum):
    READ = enum.auto()
    WRITE = enum.auto()
    CALL = enum.auto()


Xref = tuple[int, RefType]


FunctionXrefMap = Mapping[int, tuple[Xref, ...]]


ADDR_REGEX = re.compile(r"0x[0-9a-f]{6,8}")


class XrefCollector:
    seen_addrs: list[Xref]
    """List of addrs that would be replaced by a name or placeholder."""

    is_entity: Callable[[int], bool]
    """Test whether the address is a known entity in the database."""

    def __init__(self, is_entity: Callable[[int], bool]) -> None:
        self.is_entity = is_entity
        self.seen_addrs = []

    def _append_addrs(self, text: str, ref_type: RefType):
        for hex_str in ADDR_REGEX.findall(text):
            addr = int(hex_str, 16)
            if self.is_entity(addr):
                self.seen_addrs.append((addr, ref_type))

    def analyze(self, data: Buffer, start_addr: int):
        ig = InstructGen(bytes(data), start_addr, True)

        for section in ig.sections:
            if section.type == SectionType.CODE:
                for inst in section.contents:
                    inst_mnemonic, inst_op_str = inst[2:]
                    if inst_mnemonic == "ret":
                        break

                    if inst_mnemonic in JUMP_MNEMONICS:
                        continue

                    if inst_mnemonic in ("call",):
                        self._append_addrs(inst_op_str, RefType.CALL)
                        # self._append_addrs(inst_op_str, RefType.READ)
                    elif inst_mnemonic in ("mov", "fstp"):
                        dst_operand, _, src_operand = inst_op_str.partition(", ")
                        self._append_addrs(dst_operand, RefType.WRITE)
                        self._append_addrs(src_operand, RefType.READ)
                    else:
                        self._append_addrs(inst_op_str, RefType.READ)


def get_function_sample_size(db: EntityDb, image_id: ImageId, addr: int) -> int:
    """How many bytes should we read to sample the addresses used in the function?
    Use exact size if we have it, or any size estimate available."""
    ent = db.get(image_id, addr)
    if ent is not None:
        size = ent.size(image_id)
        if size is not None:
            return size

        max_size = ent.max_size(image_id)
        if max_size:
            return max_size

        # Compute the max size on demand if we cannot use any precomputed value.
        max_size = db.get_max_size(image_id, addr)
        if max_size:
            return max_size

    # Arbitrary value with the intent of overshooting the function's actual size
    # and then correcting during disassembly.
    return 1000


def get_function_xrefs(
    db: EntityDb, image_id: ImageId, binfile: Image, addr: int
) -> tuple[Xref, ...]:
    """Create lists of addresses used by this function and the way they are used.
    Filter the addresses that point to a matched variable or function entity.
    These are the xrefs we use for matching."""
    size = get_function_sample_size(db, image_id, addr)
    raw = binfile.read(addr, size)

    collector = XrefCollector(partial(db.exists, image_id))
    collector.analyze(raw, addr)

    normalized_addrs = []
    for xref_addr, ref_type in collector.seen_addrs:
        ent = db.get(image_id, xref_addr)
        # Only matched entities can be xrefs
        # because we have an address in both address spaces.
        if (
            ent
            and ent.matched
            and ent.get("type") in (EntityType.FUNCTION, EntityType.DATA)
        ):
            normalized_addr = ent.addr(ImageId.ORIG)
            assert isinstance(normalized_addr, int)
            normalized_addrs.append((normalized_addr, ref_type))

    return tuple(normalized_addrs)


def _index_xrefs(
    entry_to_xref_map: FunctionXrefMap,
) -> dict[Xref, set[int]]:
    """Invert the input that maps each CRT array entry to xrefs collected from the function set.
    Return a mapping of xrefs that point to each array entry where the xref was seen.
    """
    index: dict[Xref, set[int]] = {}
    for entry, xrefs in entry_to_xref_map.items():
        for xref in xrefs:
            index.setdefault(xref, set()).add(entry)

    return index


def _find_unique_pairs(pairs: set[tuple[int, int]]) -> set[tuple[int, int]]:
    """Return (orig, recomp) pairs where orig and recomp are each used only once."""
    orig_count = Counter(orig for orig, _ in pairs)
    recomp_count = Counter(recomp for _, recomp in pairs)
    return {
        (orig, recomp)
        for orig, recomp in pairs
        if orig_count[orig] == 1 and recomp_count[recomp] == 1
    }


def create_xref_matches(
    orig_xrefs: FunctionXrefMap,
    recomp_xrefs: FunctionXrefMap,
) -> list[tuple[int, int]]:
    """Match a set of functions from orig and recomp using their xrefs.
    This requires that xrefs have been normalized to the orig address space.

    In each pass, create connections between users of a unique xref: the xref appears only
    once in each array. Add these connections to a set. Create matches from pairs of entries
    in the set with a unique connection: the entries in each array connect only to each other.

    Non-unique connections remain in the set. These entries can not match because they connect
    to more than one other function.

    When a function is matched, it no longer uses of any of its xrefs. If this creates new unique
    xrefs, use them to create new connections. Continue until no new matches are possible.
    """

    # The input maps functions with the list of their xrefs.
    # Build the reverse map of xrefs to their function users.
    orig_index = _index_xrefs(orig_xrefs)
    recomp_index = _index_xrefs(recomp_xrefs)

    # Set of xrefs that may connect two functions. To start, limit to xrefs used in both arrays.
    candidates = orig_index.keys() & recomp_index.keys()

    # Pairs of functions connected via a unique xref.
    connections: set[tuple[int, int]] = set()

    # Output list.
    matches: list[tuple[int, int]] = []

    while True:
        for xref in candidates:
            # Use `get()` here because the xref may have no remaining users.
            orig_entries = orig_index.get(xref, ())
            recomp_entries = recomp_index.get(xref, ())
            # If the xref is unique in both arrays:
            if len(orig_entries) == 1 and len(recomp_entries) == 1:
                (orig_addr,) = orig_entries
                (recomp_addr,) = recomp_entries
                connections.add((orig_addr, recomp_addr))

        # Pull out the unique connections.
        new_matches = _find_unique_pairs(connections)
        if not new_matches:
            return matches

        matches.extend(new_matches)
        # Leave non-unique connections in the set to block
        # potential matches on new connection using the same functions.
        connections -= new_matches

        # Remove matched functions from the xref index.
        # If this results in an xref having only one user, flag it for the next pass.
        candidates = set()
        for orig_addr, recomp_addr in new_matches:
            for xrefs_by_function, index, matched_addr in (
                (orig_xrefs, orig_index, orig_addr),
                (recomp_xrefs, recomp_index, recomp_addr),
            ):
                # For each xref used by a matched function:
                for xref in xrefs_by_function[matched_addr]:
                    # Delete the function from the xref's user list
                    users = index[xref]
                    users.discard(matched_addr)
                    # If the xref has only one user left:
                    if len(users) == 1:
                        candidates.add(xref)
