import struct
import pytest
from reccmp.analysis.crt_startup import (
    find_crt_startup_labels,
    read_crt_functions,
    collect_crt_xrefs,
    CrtStartupArray,
    match_destructors,
    match_function_sets,
    read_atexit_destructor,
    read_function_set,
)
from reccmp.analysis.xref import RefType
from reccmp.compare.db import EntityDb
from reccmp.formats import PEImage
from reccmp.types import ImageId, EntityType
from .raw_image import RawImage

XCA_XCZ_RANGE = range(0x100F0000, 0x100F0020)


def test_find_crt_startup_labels_empty():
    """Should not report CRT array range if its start and end entities do not exist."""
    db = EntityDb()
    assert not find_crt_startup_labels(db, ImageId.ORIG)


def test_find_crt_startup_labels_cpp_init():
    """Should report range for C++ init array if we have entities for its start and end labels."""
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


def test_xca_functions(binfile: PEImage):
    """Should detect function set for CRT functions that follow the JMP thunk pattern."""
    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    assert array.entries == [thunk for _, thunk in XCA_THUNK_MAPPING]
    assert array.function_set == {thunk: (addr,) for addr, thunk in XCA_THUNK_MAPPING}


def test_xca_xrefs_empty(binfile: PEImage):
    """Should not detect any xrefs for addresses that have no entity in the database."""
    db = EntityDb()

    # Baseline: no entities so all xrefs are empty
    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    collect_crt_xrefs(db, ImageId.ORIG, binfile, array)

    assert not array.xrefs


def test_xca_xrefs_not_variable(binfile: PEImage):
    """Should not detect xrefs for an entity without a type."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 0x10102B28, name="g_spawnLocations")
        batch.match(0x10102B28, 0x10102B28)

    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    collect_crt_xrefs(db, ImageId.ORIG, binfile, array)
    assert 0x1001A6C0 not in array.xrefs


def test_xca_xrefs_matched_variable(binfile: PEImage):
    """Should create xref for variable `g_spawnLocations` if all expected metadata is set."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 0x10102B28, name="g_spawnLocations", type=EntityType.DATA
        )
        batch.match(0x10102B28, 0x10102B28)

    array = read_crt_functions(binfile, XCA_XCZ_RANGE)
    collect_crt_xrefs(db, ImageId.ORIG, binfile, array)
    assert array.xrefs[0x1001A6C0] == ((0x10102B28, RefType.READ),)


def test_xrefs_combine_function_set():
    """Should detect function set for CRT functions that follow the CALL + JMP thunk pattern.
    (We need a synthetic example for this because the PE image sample does not have any to use.)
    """
    code = bytearray(0x30)
    code[0:10] = (
        b"\xe8\x0b\x00\x00\x00\xe9\x16\x00\x00\x00"  # call 0x400010, jmp 0x400020
    )
    code[0x10:0x18] = (
        b"\xc6\x05\x00\x00\x41\x00\x00"  # mov byte ptr [0x410000], 0
        b"\xc3"  # ret
    )
    code[0x20:0x28] = (
        b"\xc6\x05\x00\x00\x42\x00\x00"  # mov byte ptr [0x420000], 0
        b"\xc3"  # ret
    )
    binfile = RawImage.from_memory(bytes(code), base_addr=0x400000)

    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 0x400010, size=8)
        batch.set(ImageId.ORIG, 0x400020, size=8)
        for addr in (0x410000, 0x420000):
            batch.set(ImageId.ORIG, addr, name="test", type=EntityType.DATA)
            batch.match(addr, addr)

    array = CrtStartupArray(
        entries=[0x400000], function_set={0x400000: (0x400010, 0x400020)}
    )
    collect_crt_xrefs(db, ImageId.ORIG, binfile, array)
    assert array.xrefs == {
        0x400000: ((0x410000, RefType.WRITE), (0x420000, RefType.WRITE))
    }


def test_xca_xrefs_avoid_crash(binfile: PEImage):
    """Should handle misalignment of CRT start/end entities and not raise struct.error."""
    modified_range = range(XCA_XCZ_RANGE.start, XCA_XCZ_RANGE.stop - 1)

    try:
        read_crt_functions(binfile, modified_range)
    except struct.error:
        assert False, "Should not throw"


def test_match_function_sets_no_thunks():
    """Should match CRT array entries without function sets (thunks)."""
    x_array = CrtStartupArray(entries=[500])
    y_array = CrtStartupArray(entries=[600])
    assert match_function_sets(x_array, y_array, [(500, 600)]) == [(500, 600)]


def test_match_function_sets_thunk_in_one_array():
    """Should match the function in the array with the first thunked function
    if one array entry uses a thunk pattern and the other does not."""
    x_array = CrtStartupArray(entries=[500], function_set={500: (100,)})
    y_array = CrtStartupArray(
        entries=[600],
    )
    assert match_function_sets(x_array, y_array, [(500, 600)]) == [(100, 600)]


def test_match_function_sets_thunk_jmp_pattern():
    """Should match thunks and thunked functions. Both entries use JMP pattern."""
    x_array = CrtStartupArray(entries=[500], function_set={500: (100,)})
    y_array = CrtStartupArray(entries=[600], function_set={600: (200,)})
    assert match_function_sets(x_array, y_array, [(500, 600)]) == [
        (100, 200),
        (500, 600),
    ]


def test_match_function_sets_thunk_call_jmp_pattern():
    """Should match thunks and thunked functions. Both entries use CALL + JMP pattern."""
    x_array = CrtStartupArray(entries=[500], function_set={500: (100, 101)})
    y_array = CrtStartupArray(entries=[600], function_set={600: (200, 201)})
    assert match_function_sets(x_array, y_array, [(500, 600)]) == [
        (100, 200),
        (101, 201),
        (500, 600),
    ]


def test_match_function_sets_thunk_different_patterns():
    """Should match only the first function and the thunk if the arrays use different thunk patterns"""
    x_array = CrtStartupArray(entries=[500], function_set={500: (100, 101)})
    y_array = CrtStartupArray(entries=[600], function_set={600: (200,)})
    assert match_function_sets(x_array, y_array, [(500, 600)]) == [
        (100, 200),
        (500, 600),
    ]


CRT_CALL_JMP_PATTERNS = (
    pytest.param(
        b"\xe8\x0b\x00\x00\x00\xe9\x16\x00\x00\x00", 0x20, id="call 0x10, jmp 0x20"
    ),
    pytest.param(
        b"\xe8\x0b\x00\x00\x00\xe9\x36\x00\x00\x00", 0x40, id="call 0x10, jmp 0x40"
    ),
)


@pytest.mark.parametrize("code, jmp_dest", CRT_CALL_JMP_PATTERNS)
def test_read_function_set_call_and_jmp(code: bytes, jmp_dest: int):
    """Follows the two-instruction thunk to the function at the next 16-byte boundary
    and to the jmp destination. The called function can be larger than 16 bytes,
    so the jmp displacement varies."""
    memory = bytearray(128)
    memory[0 : len(code)] = code
    memory[0x10] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0) == (0x10, jmp_dest)
    assert not read_function_set(binfile, 0x10)


def test_read_function_set_call_next_function_and_jmp():
    """Follows the two-instruction thunk when the called function begins
    immediately after the thunk instead of at the next 16-byte boundary."""
    memory = bytearray(128)
    memory[0:10] = b"\xe8\x05\x00\x00\x00\xe9\x16\x00\x00\x00"  # call 0xa, jmp 0x20
    memory[0xA] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0) == (0xA, 0x20)


def test_read_function_set_jmp_only():
    """Follows the single-instruction thunk to the function at the next 16-byte boundary."""
    memory = bytearray(128)
    memory[0:5] = b"\xe9\x0b\x00\x00\x00"  # jmp 0x10
    memory[0x10] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0) == (0x10,)
    assert not read_function_set(binfile, 0x10)


def test_read_function_set_jmp_to_next_function():
    """Follows the single-instruction thunk when the function begins
    immediately after the thunk instead of at the next 16-byte boundary."""
    memory = bytearray(128)
    memory[0:5] = b"\xe9\x00\x00\x00\x00"  # jmp 0x5
    memory[0x5] = 0xC3  # RET

    binfile = RawImage.from_memory(bytes(memory))
    assert read_function_set(binfile, 0) == (0x5,)


CRT_NOT_THUNK_PATTERNS = (
    pytest.param(b"\xe8\x0b\x00\x00\x00\xc3", id="call without jmp (16-byte aligned)"),
    pytest.param(b"\xe8\x05\x00\x00\x00\xc3", id="call without jmp"),
    pytest.param(b"\xe8\x3b\x00\x00\x00\xc3", id="call too far away"),
    pytest.param(b"\xe9\x3b\x00\x00\x00", id="jmp too far away"),
    pytest.param(b"\xe9\xdb\xff\xff\xff", id="jmp backwards"),
)


@pytest.mark.parametrize("code", CRT_NOT_THUNK_PATTERNS)
def test_read_function_set_not_a_thunk(code: bytes):
    """The function may begin with a call or jmp. It is not a thunk unless the
    instructions match a thunk pattern exactly. Only the displacement of the
    second jmp is allowed to vary."""
    memory = bytearray(128)
    memory[0x40 : 0x40 + len(code)] = code

    binfile = RawImage.from_memory(bytes(memory))
    assert not read_function_set(binfile, 0x40)


def test_read_function_set_jmp_must_be_ahead():
    """If the CALL+JMP thunk pattern is used, expect the second function to
    follow the first. We are not certain where it will be, but (for now)
    we require the jump displacement to be positive (i.e. we jump ahead)"""
    code = b"\xe8\x0b\x00\x00\x00\xe9\xf6\xff\xff\xff"  # call 0x50, jmp 0x40
    memory = bytearray(128)
    memory[0x40 : 0x40 + len(code)] = code

    binfile = RawImage.from_memory(bytes(memory))
    assert not read_function_set(binfile, 0x40)


# PUSH 0x400030; CALL 0x400100; POP ECX; RET
ATEXIT_SETTER = b"\x68\x30\x00\x40\x00\xe8\xd6\x00\x00\x00\x59\xc3"


def test_read_atexit_destructor_setter():
    """Should read the destructor address from an atexit setter function."""
    memory = bytearray(0x200)
    memory[0x20 : 0x20 + len(ATEXIT_SETTER)] = ATEXIT_SETTER
    binfile = RawImage.from_memory(bytes(memory), base_addr=0x400000)
    assert read_atexit_destructor(binfile, 0x400020) == 0x400030


def test_read_atexit_destructor_end_of_initializer():
    """Should read the destructor address if the initializer constructs the object
    and registers the destructor itself."""
    code = (
        b"\xb9\x00\x00\x41\x00"  # mov ecx, 0x410000
        b"\xe8\xf6\x00\x00\x00"  # call 0x400100
        b"\x68\x30\x00\x40\x00"  # push 0x400030
        b"\xe8\xec\x00\x00\x00"  # call 0x400100
        b"\x59"  # pop ecx
        b"\xc3"  # ret
    )
    memory = bytearray(0x200)
    memory[0 : len(code)] = code
    binfile = RawImage.from_memory(bytes(memory), base_addr=0x400000)
    assert read_atexit_destructor(binfile, 0x400000) == 0x400030


ATEXIT_NOT_SETTER_PATTERNS = (
    pytest.param(b"\xc3", id="ret only"),
    pytest.param(b"\xb9\x00\x00\x41\x00\xe9\xf6\x00\x00\x00", id="jmp without ret"),
    pytest.param(
        b"\x68\x30\x00\x40\x00\xe8\xe6\x00\x00\x00\x83\xc4\x04\xc3",
        id="add esp instead of pop ecx",
    ),
    pytest.param(
        b"\x68\x30\x00\x40\x00\xe8\xe6\x00\x00\x00\x59\x90\xc3",
        id="instruction between pop and ret",
    ),
    pytest.param(
        b"\x68\x00\x00\x00\x10\xe8\xe6\x00\x00\x00\x59\xc3",
        id="destructor outside of the image",
    ),
)


@pytest.mark.parametrize("code", ATEXIT_NOT_SETTER_PATTERNS)
def test_read_atexit_destructor_no_match(code: bytes):
    """Should not report a destructor unless the function ends with the exact
    atexit registration sequence and the destructor is in the image."""
    memory = bytearray(0x200)
    memory[0x20 : 0x20 + len(code)] = code
    binfile = RawImage.from_memory(bytes(memory), base_addr=0x400000)
    assert read_atexit_destructor(binfile, 0x400020) is None


def test_read_atexit_destructor_invalid_addr():
    """Should not raise an exception for an address outside of the image."""
    binfile = RawImage.from_memory(bytes(0x20), base_addr=0x400000)
    assert read_atexit_destructor(binfile, 0x500000) is None


def test_read_crt_functions_destructor_call_jmp():
    """Should map the array entry to the destructor registered by the atexit setter
    of a CALL + JMP thunk."""
    memory = bytearray(0x200)
    memory[0x100:0x108] = struct.pack("<II", 0, 0x400000)  # CRT array: 0, thunk
    memory[0:10] = b"\xe8\x0b\x00\x00\x00\xe9\x16\x00\x00\x00"  # call 0x10, jmp 0x20
    memory[0x10] = 0xC3  # initializer: ret
    memory[0x20 : 0x20 + len(ATEXIT_SETTER)] = ATEXIT_SETTER
    binfile = RawImage.from_memory(bytes(memory), base_addr=0x400000)

    array = read_crt_functions(binfile, range(0x400100, 0x400108))
    assert array.function_set == {0x400000: (0x400010, 0x400020)}
    assert array.destructors == {0x400000: 0x400030}


def test_read_crt_functions_destructor_no_thunk():
    """Should map the array entry to the destructor registered at the end of an
    initializer that is not reached through a thunk."""
    code = (
        b"\xb9\x00\x00\x41\x00"  # mov ecx, 0x410000
        b"\xe8\xf6\x00\x00\x00"  # call 0x400100
        b"\x68\x30\x00\x40\x00"  # push 0x400030
        b"\xe8\xec\x00\x00\x00"  # call 0x400100
        b"\x59"  # pop ecx
        b"\xc3"  # ret
    )
    memory = bytearray(0x200)
    memory[0x180:0x188] = struct.pack("<II", 0, 0x400000)  # CRT array: 0, initializer
    memory[0 : len(code)] = code
    binfile = RawImage.from_memory(bytes(memory), base_addr=0x400000)

    array = read_crt_functions(binfile, range(0x400180, 0x400188))
    assert not array.function_set
    assert array.destructors == {0x400000: 0x400030}


def test_match_destructors():
    """Should match the destructors of matched entries if both entries register one."""
    x_array = CrtStartupArray(entries=[500, 501], destructors={500: 100, 501: 101})
    y_array = CrtStartupArray(entries=[600, 601], destructors={600: 200})
    assert match_destructors(x_array, y_array, [(500, 600), (501, 601)]) == [(100, 200)]


def test_match_destructors_none():
    """Should not match anything if no entry registers a destructor."""
    x_array = CrtStartupArray(entries=[500])
    y_array = CrtStartupArray(entries=[600])
    assert not match_destructors(x_array, y_array, [(500, 600)])
