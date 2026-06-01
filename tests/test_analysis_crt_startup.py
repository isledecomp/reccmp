import struct
import pytest
from reccmp.analysis.crt_startup import (
    get_function_fingerprint,
    find_crt_startup_labels,
    analyze_crt_startup_functions,
    CrtStartupArray,
    create_crt_matches,
    UsedAddressCollector,
    unwrap_jump,
)
from reccmp.compare.db import EntityDb
from reccmp.formats import PEImage
from reccmp.types import ImageId, EntityType
from .raw_image import RawImage

# MxCriticalSection::SetDoMutex.
# Short function that sets the g_mutex global variable at 0x10101e78.
SET_DO_MUTEX_ADDR = 0x100B6E00
G_MUTEX_ADDR = 0x10101E78


def test_get_function_fingerprint_empty(binfile: PEImage):
    """The function fingerprint will be empty if entities it references are not known."""
    db = EntityDb()
    assert not get_function_fingerprint(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR)


def test_get_function_fingerprint_unmatched(binfile: PEImage):
    """The function fingerprint will be empty if entities it references are not *matched*."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, G_MUTEX_ADDR, name="g_mutex", type=EntityType.DATA)

    assert not get_function_fingerprint(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR)


def test_get_function_fingerprint_matched(binfile: PEImage):
    """g_mutex variable is matched, and it should appear in the fingerprint for SetDoMutex"""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, G_MUTEX_ADDR, name="g_mutex", type=EntityType.DATA)
        batch.match(G_MUTEX_ADDR, G_MUTEX_ADDR)

    assert get_function_fingerprint(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR) == (
        (G_MUTEX_ADDR, True),
    )


XCA_XCZ_RANGE = range(0x100F0000, 0x100F0020)


def test_find_crt_startup_labels_empty():
    db = EntityDb()
    assert not find_crt_startup_labels(db, ImageId.ORIG)


def test_find_crt_startup_labels_cpp_init():
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, XCA_XCZ_RANGE.start, name="___xc_a")
        batch.set(ImageId.ORIG, XCA_XCZ_RANGE.stop, name="___xc_z")

    labels = find_crt_startup_labels(db, ImageId.ORIG)
    assert labels["___xc_a"] == XCA_XCZ_RANGE.start
    assert labels["___xc_z"] == XCA_XCZ_RANGE.stop


# Maps function addr to thunk.
# The thunks are what appears in the ___xc_a array.
XCA_THUNK_MAPPING = (
    (0x10092360, 0x10092350),
    (0x10012DB0, 0x10012DA0),
    (0x100145A0, 0x10014590),
    (0x1001A6D0, 0x1001A6C0),
    (0x1002A4D0, 0x1002A4C0),
    (0x1003FA20, 0x1003FA10),
    (0x100537C0, 0x100537B0),
)


def test_xca_fingerprints_empty(binfile: PEImage):
    db = EntityDb()

    # Baseline: no entities so all fingerprints are empty
    result = analyze_crt_startup_functions(db, ImageId.ORIG, binfile, XCA_XCZ_RANGE)

    assert set(result.functions.keys()) == {addr for addr, _ in XCA_THUNK_MAPPING}
    assert all(not v for v in result.functions.values())

    assert tuple(result.thunks.items()) == XCA_THUNK_MAPPING


def test_xca_fingerprints_not_variable(binfile: PEImage):
    """We have the variable's entity in the database, but its type is not set.
    This means it cannot be part of the function's fingerprint."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 0x10102B28, name="g_spawnLocations")
        batch.match(0x10102B28, 0x10102B28)

    result = analyze_crt_startup_functions(db, ImageId.ORIG, binfile, XCA_XCZ_RANGE)
    assert not result.functions[0x1001A6D0]


def test_xca_fingerprints_matched_variable(binfile: PEImage):
    """Variable entity matched and with type set.
    We should now see it in the function's fingerprint list."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 0x10102B28, name="g_spawnLocations", type=EntityType.DATA
        )
        batch.match(0x10102B28, 0x10102B28)

    result = analyze_crt_startup_functions(db, ImageId.ORIG, binfile, XCA_XCZ_RANGE)
    assert result.functions[0x1001A6D0] == ((0x10102B28, False),)


def test_xca_fingerprints_avoid_crash(binfile: PEImage):
    db = EntityDb()
    # Misaligned end address will cause struct.iter_unpack to raise struct.error.
    modified_range = range(XCA_XCZ_RANGE.start, XCA_XCZ_RANGE.stop - 1)

    try:
        analyze_crt_startup_functions(db, ImageId.ORIG, binfile, modified_range)
    except struct.error:
        assert False, "Should not throw"


def test_create_match_baseline():
    """No errors or exceptions for empty CRT arrays."""
    x_array = CrtStartupArray(functions={}, thunks={})
    y_array = CrtStartupArray(functions={}, thunks={})
    assert not create_crt_matches(x_array, y_array)


def test_create_match_single():
    """Should create match for unique fingerprint."""
    write_sample = (1234, True)
    x_array = CrtStartupArray(functions={100: (write_sample,)}, thunks={})
    y_array = CrtStartupArray(functions={200: (write_sample,)}, thunks={})
    assert create_crt_matches(x_array, y_array) == [(100, 200)]


def test_create_match_single_with_thunks_one_sided():
    """Should not add thunk match unless it exists in both arrays."""
    write_sample = (1234, True)
    x_array = CrtStartupArray(functions={100: (write_sample,)}, thunks={100: 500})
    y_array = CrtStartupArray(functions={200: (write_sample,)}, thunks={})
    assert create_crt_matches(x_array, y_array) == [(100, 200)]


def test_create_match_single_with_thunks_two_sided():
    """Should match function and thunk."""
    write_sample = (1234, True)
    x_array = CrtStartupArray(functions={100: (write_sample,)}, thunks={100: 500})
    y_array = CrtStartupArray(functions={200: (write_sample,)}, thunks={200: 600})
    assert create_crt_matches(x_array, y_array) == [(100, 200), (500, 600)]


def test_create_match_blank_fingerprint():
    """Should not match functions if their fingerprint has no addresses."""
    x_array = CrtStartupArray(functions={100: ()}, thunks={})
    y_array = CrtStartupArray(functions={200: ()}, thunks={})
    assert not create_crt_matches(x_array, y_array)


def test_create_match_non_unique_fingerprint():
    """Should not match functions if their fingerprint is not unique."""
    write_sample = (1234, True)
    x_array = CrtStartupArray(
        functions={100: (write_sample,), 200: (write_sample,)}, thunks={}
    )
    y_array = CrtStartupArray(
        functions={200: (write_sample,), 300: (write_sample,)}, thunks={}
    )
    assert not create_crt_matches(x_array, y_array)


def test_create_match_with_elimination():
    """Can create unique matches by eliminating already-matched functions."""
    write_sample = (1234, True)
    read_sample = (5000, False)
    # `write_sample` can be used to match uniquely on the first pass.
    # `read_sample` will provide a unique match after deleting the functions that contain `write_sample`.
    x_array = CrtStartupArray(
        functions={100: (read_sample,), 200: (write_sample, read_sample)},
        thunks={},
    )
    y_array = CrtStartupArray(
        functions={200: (read_sample,), 300: (write_sample, read_sample)},
        thunks={},
    )
    # Must be this order:
    assert create_crt_matches(x_array, y_array) == [
        (200, 300),
        (100, 200),
    ]


def test_collector_small_addrs_ignored():
    """Limit tested addresses to those large enough to be an EXE imagebase."""
    code = (
        b"\xc6\x05\x00\x00\x00\x00\x00"  # mov byte ptr [0x0], 0
        b"\xc6\x05\x00\x10\x00\x00\x00"  # mov byte ptr [0x1000], 0
        b"\xc6\x05\x00\x00\x40\x00\x00"  # mov byte ptr [0x400000], 0
        b"\xc6\x05\x00\x00\x00\x10\x00"  # mov byte ptr [0x10000000], 0
        b"\xc3"  # ret
    )

    collector = UsedAddressCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, True),
        (0x10000000, True),
    ]


def test_collector_repeated_addrs():
    """Collected addresses are presented in sequence and are not deduplicated.
    The caller can choose to reduce this to a set as needed."""
    code = (
        b"\xc6\x05\x00\x00\x40\x00\x00"  # mov byte ptr [0x400000], 0
        b"\xc6\x05\x00\x00\x40\x00\x00"  # mov byte ptr [0x400000], 0
        b"\x80\x3d\x00\x00\x40\x00\x00"  # cmp byte ptr [0x400000], 0x0
        b"\xc3"  # ret
    )

    collector = UsedAddressCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, True),
        (0x400000, True),
        (0x400000, False),
    ]


def test_collector_classify_float_instructions_as_read_or_write():
    """Capstone does not present float instructions with their implicit FPU register.
    Make sure FSTP is identified as a write, and the others as reads."""
    code = (
        b"\xd9\x05\x00\x10\x40\x00"  # fld dword ptr [0x401000]
        b"\xd8\x35\x00\x20\x40\x00"  # fdiv dword ptr [0x402000]
        b"\xd9\x1d\x00\x30\x40\x00"  # fstp dword ptr [0x403000]
        b"\xc3"  # ret
    )

    collector = UsedAddressCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x401000, False),
        (0x402000, False),
        (0x403000, True),
    ]


def test_collector_not_all_dst_operands_are_writes():
    code = (
        b"\x80\x3d\x00\x00\x40\x00\x00"  # cmp byte ptr [0x400000], 0x0
        b"\xf6\x05\x00\x00\x41\x00\x08"  # test byte ptr [0x410000], 0x8
        b"\xc3"  # ret
    )

    collector = UsedAddressCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, False),
        (0x410000, False),
    ]


def test_collector_calls_and_jumps():
    """Jumps are ignored. Calls are collected as read addresses.
    (We may choose to classify them differently in the future.)"""
    code = (
        b"\xe8\xfb\x0f\x00\x00"  # call 0x401000
        b"\xe9\xf6\x1f\x00\x00"  # jmp 0x402000
        b"\xc3"  # ret
    )

    collector = UsedAddressCollector(lambda _: True)
    # Must set start addr here because CALLs and JMPs are relative.
    collector.analyze(code, 0x400000)

    assert collector.seen_addrs == [
        (0x401000, False),
    ]


def jump_instruction(start: int, end: int, opcode: int = 0xE9) -> bytes:
    """Create an instruction with the correct jump displacement."""
    return struct.pack("<Bi", opcode, end - start - 5)


CRT_THUNK_ORIENTATIONS = (
    (0, 5),  # Thunk first, no gap
    (0, 16),  # Thunk first, 16-byte-aligned
    (5, 0),  # Function first, no gap
    (16, 0),  # Function first, 16-byte-aligned
)


@pytest.mark.parametrize("opcode", (0xE8, 0xE9))  # CALL, JMP
@pytest.mark.parametrize("thunk_addr, func_addr", CRT_THUNK_ORIENTATIONS)
def test_unwrap_jump(thunk_addr: int, func_addr: int, opcode: int):
    """Testing situations where we assume a jump or call is a thunk."""
    thunk = jump_instruction(start=thunk_addr, end=func_addr, opcode=opcode)

    # Prepare the instructions
    memory = bytearray(128)
    memory[thunk_addr : thunk_addr + 5] = thunk
    memory[func_addr] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert unwrap_jump(binfile, thunk_addr) == (True, func_addr)
    assert unwrap_jump(binfile, func_addr) == (False, func_addr)


CRT_NOT_A_THUNK_ORIENTATIONS = (
    (0, 0x40),  # Thunk first
    (0x60, 0),  # Function first
)


@pytest.mark.parametrize("opcode", (0xE8, 0xE9))  # CALL, JMP
@pytest.mark.parametrize("thunk_addr, func_addr", CRT_NOT_A_THUNK_ORIENTATIONS)
def test_unwrap_jump_outside_thresh(thunk_addr: int, func_addr: int, opcode: int):
    """Testing where we do NOT assume a jump or call is a thunk."""
    thunk = jump_instruction(start=thunk_addr, end=func_addr, opcode=opcode)

    # Prepare the instructions
    memory = bytearray(128)
    memory[thunk_addr : thunk_addr + 5] = thunk
    memory[func_addr] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert unwrap_jump(binfile, thunk_addr) == (False, thunk_addr)
    assert unwrap_jump(binfile, func_addr) == (False, func_addr)
