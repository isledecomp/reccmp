import enum
import struct
from dataclasses import dataclass
from typing import Iterator
from typing_extensions import Buffer
from reccmp.compare.asm.const import JUMP_MNEMONICS
from reccmp.compare.asm.instgen import (
    DisasmLiteInst,
    InstructGen,
    SectionType,
)
from reccmp.compare.asm.parse import ParseAsm
from reccmp.compare.asm.replacement import AddrTestProtocol
from reccmp.compare.functions import create_valid_addr_lookup
from reccmp.formats import PEImage
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb


class CrtStartupArrayType(enum.Enum):
    C_INIT = enum.auto()
    CPP_INIT = enum.auto()
    C_PRE_TERM = enum.auto()
    C_TERM = enum.auto()


_CRT_STARTUP_ARRAY_LABELS = (
    "___xi_a",
    "___xi_z",
    "___xc_a",
    "___xc_z",
    "___xp_a",
    "___xp_z",
    "___xt_a",
    "___xt_z",
)


_CRT_STARTUP_ARRAY_BOUNDARIES = {
    CrtStartupArrayType.C_INIT: ("___xi_a", "___xi_z"),
    CrtStartupArrayType.CPP_INIT: ("___xc_a", "___xc_z"),
    CrtStartupArrayType.C_PRE_TERM: ("___xp_a", "___xp_z"),
    CrtStartupArrayType.C_TERM: ("___xt_a", "___xt_z"),
}


_CRT_FUNCTION_NAMES = {
    CrtStartupArrayType.C_INIT: "$CRT_C_Initializer",
    CrtStartupArrayType.CPP_INIT: "$CRT_CPP_Initializer",
    CrtStartupArrayType.C_PRE_TERM: "$CRT_C_Pre-Terminator",
    CrtStartupArrayType.C_TERM: "$CRT_C_Terminator",
}


@dataclass
class CrtStartupArray:
    """Result from analyzing functions in a CRT startup array.
    The functions within are called before main() is executed.
    For example: addresses of C++ initializer functions are between
    the labels ___xc_a and ___xc_z."""

    functions: dict[int, tuple[int, ...]]
    """Maps function address -> (sorted) list of matched entities used in
    the function, normalized to orig address space. These fingerprints are
    used to match initializer functions in orig and recomp."""

    thunks: dict[int, int]
    """Maps thunked initializer function to the thunk address.
    The thunk is what actually appeared in the ___xc_a/z list."""


class UsedAddressCollector(ParseAsm):
    """Wraps the asm sanitize mechanism that detects pointers and address literals
    used in the function. Instead of replacing the addresses, just store them
    in a list for review."""

    seen_addrs: list[int]
    """List of addrs that would be replaced by a name or placeholder."""

    def __init__(self, addr_test: AddrTestProtocol | None = None) -> None:
        super().__init__(addr_test, None, True)
        self.seen_addrs = []

    def lookup(self, addr: int, exact: bool = False, indirect: bool = False) -> None:
        self.seen_addrs.append(addr)

    def analyze(self, data: Buffer, start_addr: int):
        ig = InstructGen(bytes(data), start_addr, self.is_32bit)

        instructions = (
            inst
            for section in ig.sections
            for inst in section.contents
            if section.type == SectionType.CODE
        )

        for inst in instructions:
            assert isinstance(inst, DisasmLiteInst)
            if "0x" in inst.op_str and (
                inst.mnemonic in JUMP_MNEMONICS or inst.size > 4 or not self.is_32bit
            ):
                # Reading the function will call the lookup() function
                # and collect the addresses.
                self.sanitize(inst)

            # The functions we are looking at should not have complex logic
            # that creates multiple exits.
            if inst.mnemonic == "ret":
                break


def get_function_fingerprint(
    db: EntityDb, image_id: ImageId, binfile: PEImage, addr: int
) -> tuple[int, ...]:
    # 64 bytes chosen arbitrarily.
    # These functions are typically short, and we only need
    # to read enough to create the fingerprint.
    raw = binfile.read(addr, 64)

    addr_test = create_valid_addr_lookup(db, image_id, binfile)
    collector = UsedAddressCollector(addr_test)
    collector.analyze(raw, addr)

    normalized_addrs = []
    for ca in collector.seen_addrs:
        ent = db.get(image_id, ca)
        # Only matched entities are candidates for the fingerprint
        # because we have an address in both address spaces.
        if ent and ent.matched and ent.get("type") == EntityType.DATA:
            normalized_addr = ent.addr(ImageId.ORIG)
            assert isinstance(normalized_addr, int)
            normalized_addrs.append(normalized_addr)

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


def unwrap_jump(binfile: PEImage, addr: int) -> tuple[bool, int]:
    """If there is a 5-byte JMP or CALL instruction at the given address,
    follow it by calculating the destination address.
    Returns either (True, jmp_destination) or (False, starting_addr)."""
    jmp = binfile.read(addr, 5)
    # Check for CALL (0xE8) or JMP (0xE9) opcodes.
    if jmp[0] in (0xE8, 0xE9):
        (offset,) = struct.unpack("<i", jmp[1:])
        # Follow the jump only if it is small.
        if abs(offset) <= 16:
            # Add 5 because the offset is based on the address of
            # the *next* instruction after the JMP.
            return (True, addr + 5 + offset)

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


def analyze_crt_startup(
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
    # Don't match using blank fingerprints
    invert_orig = dict(
        (fp, addr) for addr, fp in orig_array.functions.items() if fp is not None
    )
    invert_recomp = dict(
        (fp, addr) for addr, fp in recomp_array.functions.items() if fp is not None
    )

    matches = []

    for fingerprint, orig_addr in invert_orig.items():
        if fingerprint in invert_recomp:
            recomp_addr = invert_recomp[fingerprint]
            matches.append((orig_addr, recomp_addr))

            if orig_addr in orig_array.thunks and recomp_addr in recomp_array.thunks:
                orig_thunk = orig_array.thunks[orig_addr]
                recomp_thunk = recomp_array.thunks[recomp_addr]
                matches.append((orig_thunk, recomp_thunk))

    return matches


def match_crt_startup(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    crt_orig = tuple(analyze_crt_startup(db, ImageId.ORIG, orig_bin))
    crt_recomp = tuple(analyze_crt_startup(db, ImageId.RECOMP, recomp_bin))

    matches = []

    for (orig_type, orig_array), (recomp_type, recomp_array) in zip(
        crt_orig, crt_recomp
    ):
        # Safety
        assert orig_type == recomp_type
        if orig_array and recomp_array:
            matches.extend(create_crt_matches(orig_array, recomp_array))

    with db.batch() as batch:
        for image_id, crt_arrays in (
            (ImageId.ORIG, crt_orig),
            (ImageId.RECOMP, crt_recomp),
        ):
            for array_type, array in crt_arrays:
                if array is None:
                    continue

                name = _CRT_FUNCTION_NAMES[array_type]
                assert isinstance(name, str)

                for addr in array.functions.keys():
                    batch.set(
                        image_id,
                        addr,
                        type=EntityType.FUNCTION,
                        name=name,
                    )

                    if addr in array.thunks:
                        thunk_addr = array.thunks[addr]
                        batch.set(
                            image_id,
                            thunk_addr,
                            type=EntityType.FUNCTION,
                            name=name,
                        )

        for orig_addr, recomp_addr in matches:
            batch.match(orig_addr, recomp_addr)
