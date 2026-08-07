import struct
import pytest
from reccmp.analysis.crt_startup import (
    get_function_fingerprint,
    find_crt_startup_labels,
    read_crt_functions,
    fingerprint_crt_functions,
    CrtStartupArray,
    create_crt_matches,
    UsedAddressCollector,
    unwrap_jump,
    find_initializer_atexit_helpers,
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
    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    fingerprint_crt_functions(db, ImageId.ORIG, binfile, array)

    assert set(array.functions.keys()) == {addr for addr, _ in XCA_THUNK_MAPPING}
    assert all(not v for v in array.functions.values())

    assert tuple(array.thunks.items()) == XCA_THUNK_MAPPING


def test_xca_fingerprints_not_variable(binfile: PEImage):
    """We have the variable's entity in the database, but its type is not set.
    This means it cannot be part of the function's fingerprint."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 0x10102B28, name="g_spawnLocations")
        batch.match(0x10102B28, 0x10102B28)

    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    fingerprint_crt_functions(db, ImageId.ORIG, binfile, array)
    assert not array.functions[0x1001A6D0]


def test_xca_fingerprints_matched_variable(binfile: PEImage):
    """Variable entity matched and with type set.
    We should now see it in the function's fingerprint list."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 0x10102B28, name="g_spawnLocations", type=EntityType.DATA
        )
        batch.match(0x10102B28, 0x10102B28)

    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    fingerprint_crt_functions(db, ImageId.ORIG, binfile, array)
    assert array.functions[0x1001A6D0] == ((0x10102B28, False),)


def test_xca_fingerprints_avoid_crash(binfile: PEImage):
    # Misaligned end address will cause struct.iter_unpack to raise struct.error.
    modified_range = range(XCA_XCZ_RANGE.start, XCA_XCZ_RANGE.stop - 1)

    try:
        read_crt_functions(binfile, modified_range)
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


CRT_CALL_JMP_PATTERNS = (
    b"\xe8\x0b\x00\x00\x00\xe9\x16\x00\x00\x00",  # call 0x10, jmp 0x20
    b"\xe8\x0b\x00\x00\x00\xe9\x36\x00\x00\x00",  # call 0x10, jmp 0x40
)


@pytest.mark.parametrize("code", CRT_CALL_JMP_PATTERNS)
def test_unwrap_jump_call_and_jmp(code: bytes):
    """Follows the two-instruction thunk to the function at the next 16-byte boundary.
    The called function can be larger than 16 bytes, so the jmp displacement varies."""
    memory = bytearray(128)
    memory[0 : len(code)] = code
    memory[0x10] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert unwrap_jump(binfile, 0) == (True, 0x10)
    assert unwrap_jump(binfile, 0x10) == (False, 0x10)


def test_unwrap_jump_jmp_only():
    """Follows the single-instruction thunk to the function at the next 16-byte boundary."""
    memory = bytearray(128)
    memory[0:5] = b"\xe9\x0b\x00\x00\x00"  # jmp 0x10
    memory[0x10] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert unwrap_jump(binfile, 0) == (True, 0x10)
    assert unwrap_jump(binfile, 0x10) == (False, 0x10)


CRT_NOT_THUNK_PATTERNS = (
    b"\xe8\x0b\x00\x00\x00\xc3",  # call +0x10 with no jmp to follow it
    b"\xe8\x3b\x00\x00\x00\xc3",  # call +0x40
    b"\xe9\x3b\x00\x00\x00",  # jmp +0x40
    b"\xe9\xdb\xff\xff\xff",  # jmp -0x20
)


@pytest.mark.parametrize("code", CRT_NOT_THUNK_PATTERNS)
def test_unwrap_jump_not_a_thunk(code: bytes):
    """The function may begin with a call or jmp. It is not a thunk
    unless the displacements match a thunk pattern exactly."""
    memory = bytearray(128)
    memory[0x40 : 0x40 + len(code)] = code

    binfile = RawImage.from_memory(bytes(memory))
    assert unwrap_jump(binfile, 0x40) == (False, 0x40)


def test_find_initializer_atexit_helpers_by_registered_function_identity():
    initializer, helper, atexit = 0x0, 0x20, 0x30
    call_addr = initializer + 5
    rel = atexit - (call_addr + 5)
    code = (
        b"\x68" + struct.pack("<I", helper) + b"\xe8" + struct.pack("<i", rel) + b"\xc3"
    )
    image = RawImage.from_memory(code + b"\x90" * 0x40)
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, initializer, type=EntityType.FUNCTION, size=len(code))
        batch.set(ImageId.ORIG, helper, type=EntityType.FUNCTION, size=1)
        batch.set(
            ImageId.ORIG, atexit, type=EntityType.FUNCTION, name="_atexit", size=1
        )

    assert find_initializer_atexit_helpers(
        db, ImageId.ORIG, image, iter([initializer])  # type: ignore[arg-type]
    ) == {initializer: (helper,)}


def test_find_initializer_atexit_helpers_rejects_non_atexit_call():
    initializer, helper, target = 0x0, 0x20, 0x30
    rel = target - (initializer + 10)
    code = (
        b"\x68" + struct.pack("<I", helper) + b"\xe8" + struct.pack("<i", rel) + b"\xc3"
    )
    image = RawImage.from_memory(code + b"\x90" * 0x40)
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, initializer, type=EntityType.FUNCTION, size=len(code))
        batch.set(ImageId.ORIG, helper, type=EntityType.FUNCTION, size=1)
        batch.set(
            ImageId.ORIG, target, type=EntityType.FUNCTION, name="ordinary", size=1
        )

    assert find_initializer_atexit_helpers(
        db, ImageId.ORIG, image, iter([initializer])  # type: ignore[arg-type]
    ) == {initializer: ()}
