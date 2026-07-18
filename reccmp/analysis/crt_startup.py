import enum
import re
import struct
from dataclasses import dataclass
from typing import Callable, Iterator
from typing_extensions import Buffer
from reccmp.compare.asm.const import JUMP_MNEMONICS
from reccmp.compare.asm.instgen import (
    InstructGen,
    SectionType,
)
from reccmp.formats import Image, PEImage
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb


class CrtStartupArrayType(enum.Enum):
    C_INIT = enum.auto()
    CPP_INIT = enum.auto()
    C_PRE_TERM = enum.auto()
    C_TERM = enum.auto()


_CRT_STARTUP_ARRAY_BOUNDARIES = {
    CrtStartupArrayType.C_INIT: ("___xi_a", "___xi_z"),
    CrtStartupArrayType.CPP_INIT: ("___xc_a", "___xc_z"),
    CrtStartupArrayType.C_PRE_TERM: ("___xp_a", "___xp_z"),
    CrtStartupArrayType.C_TERM: ("___xt_a", "___xt_z"),
}

_CRT_STARTUP_ARRAY_LABELS = [
    label for pair in _CRT_STARTUP_ARRAY_BOUNDARIES.values() for label in pair
]


_CRT_FUNCTION_NAMES = {
    CrtStartupArrayType.C_INIT: "$CRT_C_Initializer",
    CrtStartupArrayType.CPP_INIT: "$CRT_CPP_Initializer",
    CrtStartupArrayType.C_PRE_TERM: "$CRT_C_Pre-Terminator",
    CrtStartupArrayType.C_TERM: "$CRT_C_Terminator",
}


def get_crt_function_name(type_: CrtStartupArrayType) -> str:
    return _CRT_FUNCTION_NAMES[type_]


UsedAddress = tuple[int, bool]


@dataclass
class CrtStartupArray:
    """Result from analyzing functions in a CRT startup array.
    The functions within are called before main() is executed.
    For example: addresses of C++ initializer functions are between
    the labels ___xc_a and ___xc_z."""

    functions: dict[int, tuple[UsedAddress, ...]]
    """Maps function address -> (sorted) list of matched entities used in
    the function, normalized to orig address space. These fingerprints are
    used to match initializer functions in orig and recomp."""

    thunks: dict[int, int]
    """Maps thunked initializer function to the thunk address.
    The thunk is what actually appeared in the ___xc_a/z list."""


ADDR_REGEX = re.compile(r"0x[0-9a-f]{6,8}")


class UsedAddressCollector:
    seen_addrs: list[UsedAddress]
    """List of addrs that would be replaced by a name or placeholder."""

    is_entity: Callable[[int], bool]
    """Test whether the address is a known entity in the database."""

    def __init__(self, is_entity: Callable[[int], bool]) -> None:
        self.is_entity = is_entity
        self.seen_addrs = []

    def _append_addrs(self, text: str, is_write: bool):
        for hex_str in ADDR_REGEX.findall(text):
            addr = int(hex_str, 16)
            if self.is_entity(addr):
                self.seen_addrs.append((addr, is_write))

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

                    if inst_mnemonic in ("mov", "fstp"):
                        dst_operand, _, src_operand = inst_op_str.partition(", ")
                        self._append_addrs(dst_operand, True)
                        self._append_addrs(src_operand, False)
                    else:
                        self._append_addrs(inst_op_str, False)


def get_function_sample_size(db: EntityDb, image_id: ImageId, addr: int) -> int:
    """How many bytes should we read to sample the addresses used in the function?
    Use exact size if we have it, or any size estimate available."""
    ent = db.get(image_id, addr)
    if ent is not None:
        size = ent.size(image_id)
        if size is not None:
            return size

        max_size = db.get_max_size(image_id, addr)
        if max_size:
            return max_size

    # Arbitrary value with the intent of overshooting the function's actual size
    # and then correcting during disassembly.
    return 1000


def get_function_fingerprint(
    db: EntityDb, image_id: ImageId, binfile: PEImage, addr: int
) -> tuple[UsedAddress, ...]:
    """Create lists of addresses written to and read from by this function.
    Filter the addresses that point to a matched variable entity.
    These two lists of identifying characteristics about the function
    are the "fingerprint" we can use for matching."""
    size = get_function_sample_size(db, image_id, addr)
    raw = binfile.read(addr, size)

    def entity_exists(test_addr: int) -> bool:
        return db.get(image_id, test_addr, exact=True) is not None

    collector = UsedAddressCollector(entity_exists)
    collector.analyze(raw, addr)

    normalized_addrs = []
    for sample_addr, is_write in collector.seen_addrs:
        ent = db.get(image_id, sample_addr)
        # Only matched entities are candidates for the fingerprint
        # because we have an address in both address spaces.
        if ent and ent.matched and ent.get("type") == EntityType.DATA:
            normalized_addr = ent.addr(ImageId.ORIG)
            assert isinstance(normalized_addr, int)
            normalized_addrs.append((normalized_addr, is_write))

    return tuple(normalized_addrs)


def read_crt_array(binfile: PEImage, span: range) -> Iterator[int]:
    """Read 4-byte (dword) pointers from the specified range.
    Excludes the first element, a zero."""
    try:
        for (addr,) in struct.iter_unpack("<I", binfile.read(span.start, len(span))):
            if addr != 0:
                yield addr
    except struct.error:
        # Don't crash on bad user input: the start or end addrs are incorrect
        pass


def find_crt_startup_labels(db: EntityDb, image_id: ImageId) -> dict[str, int]:
    found = {}

    for ent in db.all(image_id):
        name = ent.get("name")
        if name is not None and name in _CRT_STARTUP_ARRAY_LABELS:
            addr = ent.addr(image_id)
            assert isinstance(addr, int)
            found[name] = addr

            if len(found) == len(_CRT_STARTUP_ARRAY_LABELS):
                break

    return found


INITIALIZER_THUNK_MAX_JUMP_OFFSET = 16
"""Some MSVC dynamic initializers are thunked. By observation, the thunked function is
usually at the next 16-byte-aligned address. Tweak this value if necessary."""


def unwrap_jump(binfile: Image, addr: int) -> tuple[bool, int]:
    """If there is a 5-byte JMP or CALL instruction at the given address,
    follow it by calculating the destination address.
    Returns either (True, jmp_destination) or (False, starting_addr)."""
    jmp = binfile.read(addr, 5)
    # Check for CALL (0xE8) or JMP (0xE9) opcodes.
    if jmp[0] in (0xE8, 0xE9):
        (offset,) = struct.unpack("<i", jmp[1:])
        # Add 5 because the offset is based on the address of
        # the *next* instruction after the JMP.
        destination = addr + 5 + offset
        # Follow the jump only if it is small.
        if abs(destination - addr) <= INITIALIZER_THUNK_MAX_JUMP_OFFSET:
            return (True, destination)

    return (False, addr)


def analyze_crt_startup_functions(
    db: EntityDb, image_id: ImageId, binfile: PEImage, span: range
) -> CrtStartupArray:
    """Read the functions for a single CRT startup array and find the identifying "fingerprint"
    of which variables are referenced."""
    funcs = tuple(read_crt_array(binfile, span))

    fingerprints = {}
    thunks = {}

    for xc_addr in funcs:
        # n.b. The first value in the array is zero. It was excluded by read_crt_array.
        was_thunk, real_addr = unwrap_jump(binfile, xc_addr)
        fp = get_function_fingerprint(db, image_id, binfile, real_addr)
        fingerprints[real_addr] = fp
        if was_thunk:
            thunks[real_addr] = xc_addr

    return CrtStartupArray(fingerprints, thunks)


def detect_crt_startup_arrays(
    db: EntityDb, image_id: ImageId, binfile: PEImage
) -> Iterator[tuple[CrtStartupArrayType, CrtStartupArray | None]]:
    """For the CRT startup arrays in the given binary, if the start and end labels are known,
    analyze the functions in each array."""
    labels = find_crt_startup_labels(db, image_id)
    for array_type, (label_start, label_end) in _CRT_STARTUP_ARRAY_BOUNDARIES.items():
        if label_start in labels and label_end in labels:
            array_range = range(labels[label_start], labels[label_end])
            yield (
                array_type,
                analyze_crt_startup_functions(db, image_id, binfile, array_range),
            )
        else:
            yield (array_type, None)


def create_crt_matches(
    orig_array: CrtStartupArray, recomp_array: CrtStartupArray
) -> list[tuple[int, int]]:
    """Match CRT startup functions from one array to other based on which addresses they use."""

    combined_map: dict[UsedAddress, set[tuple[ImageId, int]]] = {}
    eliminated: set[tuple[ImageId, int]] = set()
    matches = []

    # Each array contains the list of startup functions with attached list of sampled addresses.
    # Sampled addresses are already normalized to the original binary address space.
    # Use this as our key to connect startup functions in both orig and recomp based on which
    # addresses are used, and how (reads or writes).
    for image_id, array in ((ImageId.ORIG, orig_array), (ImageId.RECOMP, recomp_array)):
        for func_addr, addr_samples in array.functions.items():
            for sample in addr_samples:
                combined_map.setdefault(sample, set()).add((image_id, func_addr))

    while True:
        matched_this_pass = False

        # Remove startup functions matched on a previous pass.
        for value in combined_map.values():
            value -= eliminated

        # Sampled address are separated by whether the function reads or writes to them.
        # Read is not a superset for write, meaning: if the function only writes
        # to the address, the function address will only be in the `is_write=True` bucket.
        # With that separation, match any addresses where the bucket has
        # exactly one sample from orig and exactly one sample from recomp.
        for _, func_addrs in combined_map.items():
            if len(func_addrs) == 2:
                [(img_x, addr_x), (img_y, addr_y)] = func_addrs
                if img_x != img_y:
                    # These are sets, so order is not guaranteed.
                    # Figure out which address is orig and which is recomp.
                    orig_addr = addr_x if img_x == ImageId.ORIG else addr_y
                    recomp_addr = addr_y if img_y == ImageId.RECOMP else addr_x
                    matches.append((orig_addr, recomp_addr))
                    eliminated.update(func_addrs)
                    matched_this_pass = True
                    # Break because we need to remove the addresses we just matched
                    # to prevent a double match.
                    break

        if not matched_this_pass:
            break

    # Add any pairs of thunks that point to an already matched function.
    thunks = []
    for orig_addr, recomp_addr in matches:
        if orig_addr in orig_array.thunks and recomp_addr in recomp_array.thunks:
            thunks.append(
                (orig_array.thunks[orig_addr], recomp_array.thunks[recomp_addr])
            )

    matches.extend(thunks)
    return matches
