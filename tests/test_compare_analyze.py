from unittest.mock import Mock, patch
import pytest
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.formats.image import ImageImport, ImageRegion
from reccmp.isledecomp.formats import PEImage
from reccmp.isledecomp.types import EntityType, ImageId
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
    InvalidStringError,
)
from reccmp.isledecomp.compare.analyze import (
    create_analysis_floats,
    create_analysis_strings,
    create_thunks,
    create_analysis_vtordisps,
    complete_partial_strings,
    create_imports,
    create_import_thunks,
)


@pytest.fixture(name="db")
def fixture_db():
    return EntityDb()


def get_ref_addr(db: EntityDb, img: ImageId, addr: int) -> int | None:
    """Helper function to retrieve the ref address from the refs table.
    It is not visible through the ReccmpEntity / ReccmpMatch API."""
    for (ref,) in db.sql.execute(
        "SELECT ref FROM refs WHERE img = ? AND addr = ?", (img, addr)
    ):
        return ref

    return None


def get_ref_displacement(
    db: EntityDb, img: ImageId, addr: int
) -> tuple[int, int] | None:
    """Helper function to retrieve the displacement from the refs table.
    It is not visible through the ReccmpEntity / ReccmpMatch API."""
    for disp in db.sql.execute(
        "SELECT disp0, disp1 FROM refs WHERE img = ? AND addr = ?", (img, addr)
    ):
        return disp

    return None


def test_create_analysis_strings(db: EntityDb):
    """Should add this ordinary string to the database."""
    binfile = Mock(spec=[])
    binfile.iter_string = Mock(return_value=[(100, "Hello")])
    binfile.relocations = set()

    create_analysis_strings(db, ImageId.ORIG, binfile)

    e = db.get_by_orig(100)
    assert e is not None
    assert e.get("type") == EntityType.STRING
    assert e.get("size") == 6


def test_create_analysis_strings_do_not_replace(db: EntityDb):
    """Should not replace user data with the string found by automated search."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.FLOAT)

    binfile = Mock(spec=[])
    binfile.iter_string = Mock(return_value=[(100, "Hello")])
    binfile.relocations = set()

    create_analysis_strings(db, ImageId.ORIG, binfile)

    e = db.get_by_orig(100)
    assert e is not None
    assert e.get("type") != EntityType.STRING


def test_create_analysis_strings_not_relocated(db: EntityDb):
    """Should not add the string if its address is the site of a relocation.
    i.e. We know this is a pointer, despite how it appears."""
    binfile = Mock(spec=[])
    binfile.iter_string = Mock(return_value=[(100, "Hello")])
    binfile.relocations = {100}

    create_analysis_strings(db, ImageId.ORIG, binfile)

    assert db.get_by_orig(100) is None


def test_create_analysis_strings_not_latin1(db: EntityDb):
    """Should not add the string if our heuristic check for Latin1 (ANSI) fails."""
    binfile = Mock(spec=[])
    # Starts with BEL character to play the Windows chord sound
    binfile.iter_string = Mock(return_value=[(100, "\x07Alert!")])
    binfile.relocations = set()

    create_analysis_strings(db, ImageId.ORIG, binfile)

    assert db.get_by_orig(100) is None


def test_create_thunks(db: EntityDb):
    """Should create entities for each thunk in the PE image's list"""
    binfile = Mock(spec=[])
    binfile.thunks = [(100, 200)]

    create_thunks(db, ImageId.ORIG, binfile)

    e = db.get_by_orig(100)
    assert e is not None
    assert e.get("type") == EntityType.THUNK
    assert e.get("size") == 5


def test_create_thunks_do_not_replace(db: EntityDb):
    """Do not overwrite an existing entity with a thunk"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.FUNCTION, size=500)

    binfile = Mock(spec=[])
    binfile.thunks = [(100, 200)]

    create_thunks(db, ImageId.ORIG, binfile)

    e = db.get_by_orig(100)
    assert e is not None
    assert e.get("type") == EntityType.FUNCTION
    assert e.get("size") != 5
    assert e.get("ref_orig") is None


def test_create_analysis_floats(db: EntityDb):
    binfile = Mock(spec=[])

    with patch(
        "reccmp.isledecomp.compare.analyze.find_float_consts",
        return_value=[(100, 4, 0.5)],
    ):
        create_analysis_floats(db, ImageId.ORIG, binfile)

    e = db.get_by_orig(100)
    assert e is not None
    assert e.get("type") == EntityType.FLOAT
    assert e.get("size") == 4
    assert e.get("name") == "0.5"


def test_create_analysis_floats_do_not_replace(db: EntityDb):
    """Should not replace user data with the float found by automated search."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.DATA)

    binfile = Mock(spec=[])

    with patch(
        "reccmp.isledecomp.compare.analyze.find_float_consts",
        return_value=[(100, 4, 0.5)],
    ):
        create_analysis_floats(db, ImageId.ORIG, binfile)

    e = db.get_by_orig(100)
    assert e is not None
    assert e.get("type") != EntityType.FLOAT


def test_create_analysis_vtordisps(db: EntityDb, binfile: PEImage):
    """Should create entities for the detected vtordisp and the referenced functions."""
    create_analysis_vtordisps(db, ImageId.ORIG, binfile)

    # Using the first vtordisp as an example
    e = db.get_by_orig(0x1000FB50)
    assert e is not None
    assert e.get("type") == EntityType.VTORDISP
    assert e.get("size") == 8
    assert get_ref_addr(db, ImageId.ORIG, 0x1000FB50) == 0x1000FB60
    assert get_ref_displacement(db, ImageId.ORIG, 0x1000FB50) == (-4, 0)

    # Should also set up the function entity (if it does not already exist)
    e = db.get_by_orig(0x1000FB60)
    assert e is not None
    assert e.get("type") == EntityType.FUNCTION


def test_create_analysis_vtordisps_no_overwrite(db: EntityDb, binfile: PEImage):
    """Should not overwrite an entity on the referenced function if it exists."""
    with db.batch() as batch:
        # Using addrs from above example.
        batch.set_orig(0x1000FB60, type=EntityType.STRING)

    create_analysis_vtordisps(db, ImageId.ORIG, binfile)

    # For now: Don't overwrite the entity type of the referenced function.
    # This is probably fine to do in the long run, but we want to protect against
    # changes to how regular thunks are identified if/when they get their own type.
    e = db.get_by_orig(0x1000FB60)
    assert e is not None
    assert e.get("type") != EntityType.FUNCTION


def test_complete_partial_strings(db: EntityDb):
    """Should read data for a partially-initialized string entity."""
    binfile = Mock(spec=[])
    binfile.read_string = Mock(return_value=b"Hello")

    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.STRING)

    complete_partial_strings(db, ImageId.ORIG, binfile)

    # Entity size set according to string length plus null-terminator.
    e = db.get_by_orig(100)
    assert e is not None
    assert e.get("size") == 6
    assert e.name == '"Hello"'

    # Do not report a failed match if this string does not exist in both binaries.
    assert not e.get("verified")


def test_complete_partial_strings_with_nulls(db: EntityDb):
    """Should read a string with nulls if we provide the size."""
    binfile = Mock(spec=[])
    binfile.read = Mock(return_value=b"\x00test\x00")

    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.STRING, size=6)

    complete_partial_strings(db, ImageId.ORIG, binfile)

    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == '"\\x00test"'


def test_complete_partial_strings_widechar(db: EntityDb):
    """Should read data for a partially-initialized widechar entity."""
    binfile = Mock(spec=[])
    binfile.read_widechar = Mock(return_value="Hello".encode("utf-16-le"))

    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.WIDECHAR)

    complete_partial_strings(db, ImageId.ORIG, binfile)

    # Entity size set according to string length plus null-terminator.
    e = db.get_by_orig(100)
    assert e is not None
    assert e.get("size") == 12
    assert e.name == 'L"Hello"'


PARTIAL_STRING_EXCEPTIONS = (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
    InvalidStringError,
)


@pytest.mark.parametrize("ex_type", PARTIAL_STRING_EXCEPTIONS)
def test_complete_partial_strings_exceptions(db: EntityDb, ex_type: Exception):
    """Should handle various exceptions while reading string data."""

    def exception(*_):
        raise ex_type

    binfile = Mock(spec=[])
    binfile.read_string = Mock(side_effect=exception)

    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.STRING)

    complete_partial_strings(db, ImageId.ORIG, binfile)

    # Should not modify the entity.
    e = db.get_by_orig(100)
    assert e is not None
    assert e.name is None


def test_complete_partial_strings_unicode_exception(db: EntityDb):
    """Should handle a UnicodeDecodeError."""

    # This value cannot be decoded as UTF-16LE.
    value = b"\x00\xd8\x8c"
    with pytest.raises(UnicodeDecodeError):
        value.decode("utf-16-le")

    binfile = Mock(spec=[])
    binfile.read_widechar = Mock(return_value=value)

    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.WIDECHAR)

    complete_partial_strings(db, ImageId.ORIG, binfile)

    # Should not modify the entity.
    e = db.get_by_orig(100)
    assert e is not None
    assert e.name is None


def test_create_imports(db: EntityDb):
    """Should create IMPORT entities for imported functions using names or ordinals."""
    binfile = Mock(spec=[])
    binfile.imports = (
        ImageImport(addr=0x1000, module="TEST", name="Hello"),
        ImageImport(addr=0x2000, module="TEST", ordinal=10),
    )

    create_imports(db, ImageId.ORIG, binfile)

    e = db.get_by_orig(0x1000)
    assert e is not None
    assert e.get("type") == EntityType.IMPORT
    name = e.get("name")
    assert "TEST" in name
    assert "Hello" in name

    # Create mock name using the ordinal number.
    e = db.get_by_orig(0x2000)
    assert e is not None
    assert e.get("type") == EntityType.IMPORT
    name = e.get("name")
    assert "TEST" in name
    assert "10" in name


def test_create_import_thunks(db: EntityDb):
    """Should create IMPORT_THUNK entities for functions with an absolute JMP to an import descriptor."""
    binfile = Mock(spec=PEImage)
    # imports is called by find_import_thunks so we need to mock it
    # even though we do not call create_imports or create the IMPORT entity.
    binfile.imports = (ImageImport(addr=0x1000, module="TEST", name="Hello"),)
    binfile.get_code_regions = Mock(
        return_value=(ImageRegion(0x2000, b"\xff\x25\x00\x10\x00\x00"),),
    )
    binfile.relocations = set([0x2002])

    create_import_thunks(db, ImageId.ORIG, binfile)

    e = db.get(ImageId.ORIG, 0x2000)
    assert e is not None
    assert e.get("type") == EntityType.IMPORT_THUNK

    assert get_ref_addr(db, ImageId.ORIG, 0x2000) == 0x1000


def test_create_import_thunks_pe_only(db: EntityDb):
    """At the moment, we have seen import thunks on PE images only.
    create_import_thunks should be a no-op if the image is not PE."""
    pe_image = Mock(spec=PEImage)
    with patch("reccmp.isledecomp.compare.analyze.find_import_thunks") as find_fn:
        create_import_thunks(db, ImageId.ORIG, pe_image)
        find_fn.assert_called()

    image = Mock()
    with patch("reccmp.isledecomp.compare.analyze.find_import_thunks") as find_fn:
        create_import_thunks(db, ImageId.ORIG, image)
        find_fn.assert_not_called()
