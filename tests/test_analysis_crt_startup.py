from reccmp.analysis.crt_startup import (
    get_function_fingerprint,
    find_crt_startup_labels,
    analyze_crt_startup_functions,
)
from reccmp.compare.db import EntityDb
from reccmp.formats import PEImage
from reccmp.types import ImageId, EntityType

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
        G_MUTEX_ADDR,
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
    assert result.functions[0x1001A6D0] == (0x10102B28,)


def test_xca_fingerprints_avoid_crash(binfile: PEImage):
    db = EntityDb()
    # Misaligned end address will cause struct.iter_unpack to raise struct.error.
    modified_range = range(XCA_XCZ_RANGE.start, XCA_XCZ_RANGE.stop - 1)

    try:
        analyze_crt_startup_functions(db, ImageId.ORIG, binfile, modified_range)
    # pylint: disable=bare-except
    except:
        assert False, "Should not throw"
