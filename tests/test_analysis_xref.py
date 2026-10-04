from itertools import combinations
import pytest
from reccmp.analysis.xref import (
    get_function_xrefs,
    create_xref_matches,
    XrefCollector,
    RefType,
)
from reccmp.compare.db import EntityDb
from reccmp.formats import PEImage
from reccmp.types import ImageId, EntityType
from .raw_image import RawImage

# MxCriticalSection::SetDoMutex.
# Short function that sets the g_mutex global variable at 0x10101e78.
SET_DO_MUTEX_ADDR = 0x100B6E00
G_MUTEX_ADDR = 0x10101E78


def test_get_function_xrefs_empty(binfile: PEImage):
    """The function's xrefs will be empty if entities it references are not known."""
    db = EntityDb()
    assert not get_function_xrefs(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR)


def test_get_function_xrefs_unmatched(binfile: PEImage):
    """The function's xrefs will be empty if entities it references are not *matched*."""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, G_MUTEX_ADDR, name="g_mutex", type=EntityType.DATA)

    assert not get_function_xrefs(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR)


def test_get_function_xrefs_matched(binfile: PEImage):
    """g_mutex variable is matched, and it should appear in the xrefs for SetDoMutex"""
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, G_MUTEX_ADDR, name="g_mutex", type=EntityType.DATA)
        batch.match(G_MUTEX_ADDR, G_MUTEX_ADDR)

    assert get_function_xrefs(db, ImageId.ORIG, binfile, SET_DO_MUTEX_ADDR) == (
        (G_MUTEX_ADDR, RefType.WRITE),
    )


def test_get_function_xrefs_called_function():
    """Called functions appear as CALLs in the xrefs."""
    start_addr = 0x400000
    other_addr = 0x401000
    code = (
        b"\xe8\xfb\x0f\x00\x00"  # call 0x401000
        b"\xc3"  # ret
    )
    binfile = RawImage.from_memory(code, base_addr=start_addr)

    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, start_addr, size=len(code))
        batch.set(ImageId.ORIG, other_addr, name="test", type=EntityType.FUNCTION)
        batch.match(other_addr, other_addr)

    assert get_function_xrefs(db, ImageId.ORIG, binfile, start_addr) == (
        (other_addr, RefType.CALL),
    )


def test_get_function_xrefs_function_pointer():
    """Function entities that are not used in a call instruction appear as
    READ entries in the xrefs."""
    start_addr = 0x400000
    other_addr = 0x401000
    code = (
        b"\x68\x00\x10\x40\x00"  # push 0x401000
        b"\xc3"  # ret
    )
    binfile = RawImage.from_memory(code, base_addr=start_addr)

    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, start_addr, size=len(code))
        batch.set(ImageId.ORIG, other_addr, name="test", type=EntityType.FUNCTION)
        batch.match(other_addr, other_addr)

    assert get_function_xrefs(db, ImageId.ORIG, binfile, start_addr) == (
        (other_addr, RefType.READ),
    )


@pytest.mark.xfail(reason="Undecided on whether we need this")
def test_get_function_xrefs_indirect_call():
    """Indirect function calls should have their own xref category
    that is distinct from regular calls."""
    start_addr = 0x400000
    other_addr = 0x401000
    pointer = other_addr.to_bytes(4, "little")
    code = (
        b"\xff\x15\x00\x00\x40\x00"  # call dword ptr [0x400000]
        b"\xc3"  # ret
    )
    binfile = RawImage.from_memory(pointer + code, base_addr=start_addr)
    func_addr = start_addr + len(pointer)

    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, func_addr, size=len(code))
        batch.set(ImageId.ORIG, other_addr, name="test", type=EntityType.FUNCTION)
        batch.match(other_addr, other_addr)

    # TODO: Add the xrefs here if this feature is added.
    assert get_function_xrefs(db, ImageId.ORIG, binfile, func_addr)


def test_create_match_baseline():
    """No errors or exceptions for empty xref maps."""
    assert not create_xref_matches({}, {})


@pytest.mark.parametrize("ref_type", RefType)
def test_create_match_same_types(ref_type: RefType):
    """Should create match for unique xref of the same type."""
    xref = (1234, ref_type)
    x_xrefs = {100: (xref,)}
    y_xrefs = {200: (xref,)}
    assert create_xref_matches(x_xrefs, y_xrefs) == [(100, 200)]


REFTYPE_COMBINATIONS = tuple(combinations(RefType, 2))


@pytest.mark.parametrize("ref_type_x, ref_type_y", REFTYPE_COMBINATIONS)
def test_create_match_different_types(ref_type_x: RefType, ref_type_y: RefType):
    """Should not create a match for unique xrefs of different types."""
    x_xrefs = {100: ((1234, ref_type_x),)}
    y_xrefs = {200: ((1234, ref_type_y),)}
    assert not create_xref_matches(x_xrefs, y_xrefs)


@pytest.mark.parametrize("ref_type", RefType)
def test_create_match_non_unique_xref(ref_type: RefType):
    """Should not match functions if their xref is not unique."""
    xref = (1234, ref_type)
    x_xrefs = {100: (xref,), 200: (xref,)}
    y_xrefs = {200: (xref,), 300: (xref,)}
    assert not create_xref_matches(x_xrefs, y_xrefs)


@pytest.mark.parametrize("ref_type_x", RefType)
@pytest.mark.parametrize("ref_type_y", RefType)
def test_create_match_with_elimination(ref_type_x: RefType, ref_type_y: RefType):
    """Can create unique matches by eliminating already-matched functions."""
    unique_xref = (1234, ref_type_x)
    shared_xref = (5000, ref_type_y)

    # `unique_xref` can be used to match uniquely on the first pass.
    # `shared_xref` will provide a unique match after deleting the functions that use `unique_xref`.
    x_xrefs = {100: (shared_xref,), 200: (unique_xref, shared_xref)}
    y_xrefs = {200: (shared_xref,), 300: (unique_xref, shared_xref)}

    # Using `sorted()` here because matches are created uniquely, but we also want to
    # assert that there are no duplicates that would be hidden by using `set()`.
    assert sorted(create_xref_matches(x_xrefs, y_xrefs)) == [
        (100, 200),
        (200, 300),
    ]


@pytest.mark.parametrize("ref_type", RefType)
def test_create_match_duplicate_xref_same_pattern(ref_type: RefType):
    """Should match functions that use the same xref multiple times."""
    duplicate_xref = (1234, ref_type)
    x_xrefs = {500: (duplicate_xref, duplicate_xref)}
    y_xrefs = {600: (duplicate_xref, duplicate_xref)}
    assert create_xref_matches(x_xrefs, y_xrefs) == [(500, 600)]


@pytest.mark.parametrize("ref_type_x", RefType)
@pytest.mark.parametrize("ref_type_y", RefType)
def test_create_match_duplicate_xref_different_order(
    ref_type_x: RefType, ref_type_y: RefType
):
    """Should match functions that use the same xrefs despite their order."""
    xref_1 = (1000, ref_type_x)
    xref_2 = (2000, ref_type_y)
    x_xrefs = {500: (xref_1, xref_2)}
    y_xrefs = {600: (xref_2, xref_1)}
    assert create_xref_matches(x_xrefs, y_xrefs) == [(500, 600)]


@pytest.mark.parametrize("ref_type", RefType)
def test_create_match_duplicate_xref_different_count(ref_type: RefType):
    """Should match functions that use the same xref multiple times,
    even if the functions use the xref a different number of times."""
    duplicate_xref = (1234, ref_type)
    x_xrefs = {500: (duplicate_xref, duplicate_xref)}
    y_xrefs = {600: (duplicate_xref,)}
    assert create_xref_matches(x_xrefs, y_xrefs) == [(500, 600)]


@pytest.mark.parametrize("ref_type_x", RefType)
@pytest.mark.parametrize("ref_type_y", RefType)
def test_create_match_multiple_unique_xrefs(ref_type_x: RefType, ref_type_y: RefType):
    """Should match functions that share multiple unique xrefs if the pairing is unique."""
    xref_1 = (1000, ref_type_x)
    xref_2 = (2000, ref_type_y)
    x_xrefs = {500: (xref_1, xref_2)}
    y_xrefs = {600: (xref_1, xref_2)}
    assert create_xref_matches(x_xrefs, y_xrefs) == [(500, 600)]


@pytest.mark.parametrize("ref_type", RefType)
def test_create_match_reject_ambiguous_match(ref_type: RefType):
    """Should not create a match when there is more than one possible pairing."""
    xref_1 = (2000, ref_type)
    xref_2 = (3000, ref_type)
    x_xrefs = {
        100: (xref_1, xref_2),
    }
    y_xrefs = {
        200: (xref_1,),
        400: (xref_2,),
    }

    # The functions (100, 200) and (100, 400) are connected by distinct xrefs.
    # It is not clear which pairing is correct, so we return no matches.
    assert not create_xref_matches(x_xrefs, y_xrefs)


@pytest.mark.parametrize("ref_type_x", RefType)
@pytest.mark.parametrize("ref_type_y", RefType)
def test_create_match_use_unique_match_if_it_is_the_only_one(
    ref_type_x: RefType, ref_type_y: RefType
):
    """Should match using a unique xref if it is the only connection possible with a unique xref.
    Ignore potential pairings that use a _non-unique_ xref."""
    xref_1 = (1234, ref_type_x)
    xref_2 = (5000, ref_type_y)
    x_xrefs = {
        100: (xref_1,),
        200: (xref_2,),
        300: (xref_2,),
    }
    y_xrefs = {
        400: (xref_1, xref_2),
    }

    # Match (100, 400) using xref_1 because it is a unique xref.
    # xref_2 is used by multiple functions in X. Potential pairings (200, 400) and (300, 400) are not considered.
    assert create_xref_matches(x_xrefs, y_xrefs) == [(100, 400)]


def test_create_match_use_unique_xref_as_soon_as_it_is_found():
    """Should match any pairs of functions that use a unique xref on the first pass.
    This is so that address order does not play a role in matching."""
    xref_1 = (1000, RefType.READ)
    xref_2 = (2000, RefType.WRITE)
    xref_3 = (3000, RefType.WRITE)
    x_xrefs = {
        100: (xref_1, xref_2),
        300: (xref_1, xref_3),
    }
    y_xrefs = {
        200: (xref_2,),
        400: (xref_1,),
        500: (xref_3,),
    }
    # Matches (100, 200) using xref_2 and (300, 500) using xref_3 are created simultaneously.
    # Should not match (300, 500) because xref_1 is not unique on the X side.
    assert sorted(create_xref_matches(x_xrefs, y_xrefs)) == [(100, 200), (300, 500)]


def test_create_match_reject_apparent_unique_match_after_elimination():
    """Should remember ambiguous pairings that cannot result in a match.
    Elimination may create apparent unique pairings that must be rejected."""
    xref_1 = (1000, RefType.READ)
    xref_2 = (2000, RefType.READ)
    xref_3 = (3000, RefType.READ)
    xref_4 = (4000, RefType.READ)

    x_xrefs = {
        100: (xref_1,),
        200: (xref_2,),
        300: (xref_3,),
        400: (xref_3, xref_4),
    }
    y_xrefs = {
        1000: (xref_1, xref_2, xref_3),
        2000: (xref_4,),
    }
    # On the first pass, (400, 2000) match via unique xref_4.
    # (100, 1000) and (200, 1000) also appear using unique xref_1 and xref_2.
    # We cannot create a match on those functions because of the ambiguity.
    # On the second pass, with 400 eliminated, xref_3 becomes unique, so the set of pairs becomes:
    # { (100, 1000), (200, 1000), (300, 1000) }. We cannot return a match from this set.
    assert create_xref_matches(x_xrefs, y_xrefs) == [(400, 2000)]


def test_collector_small_addrs_ignored():
    """Limit tested addresses to those large enough to be an EXE imagebase."""
    code = (
        b"\xc6\x05\x00\x00\x00\x00\x00"  # mov byte ptr [0x0], 0
        b"\xc6\x05\x00\x10\x00\x00\x00"  # mov byte ptr [0x1000], 0
        b"\xc6\x05\x00\x00\x40\x00\x00"  # mov byte ptr [0x400000], 0
        b"\xc6\x05\x00\x00\x00\x10\x00"  # mov byte ptr [0x10000000], 0
        b"\xc3"  # ret
    )

    collector = XrefCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, RefType.WRITE),
        (0x10000000, RefType.WRITE),
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

    collector = XrefCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, RefType.WRITE),
        (0x400000, RefType.WRITE),
        (0x400000, RefType.READ),
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

    collector = XrefCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x401000, RefType.READ),
        (0x402000, RefType.READ),
        (0x403000, RefType.WRITE),
    ]


def test_collector_not_all_dst_operands_are_writes():
    """Should check instruction mnemonic when deciding RefType."""
    code = (
        b"\x80\x3d\x00\x00\x40\x00\x00"  # cmp byte ptr [0x400000], 0x0
        b"\xf6\x05\x00\x00\x41\x00\x08"  # test byte ptr [0x410000], 0x8
        b"\xc3"  # ret
    )

    collector = XrefCollector(lambda _: True)
    collector.analyze(code, 0)

    assert collector.seen_addrs == [
        (0x400000, RefType.READ),
        (0x410000, RefType.READ),
    ]


def test_collector_calls_and_jumps():
    """Jumps are ignored. Calls are collected as exec addresses."""
    code = (
        b"\xe8\xfb\x0f\x00\x00"  # call 0x401000
        b"\xe9\xf6\x1f\x00\x00"  # jmp 0x402000
        b"\xc3"  # ret
    )

    collector = XrefCollector(lambda _: True)
    # Must set start addr here because CALLs and JMPs are relative.
    collector.analyze(code, 0x400000)

    assert collector.seen_addrs == [
        (0x401000, RefType.CALL),
    ]
