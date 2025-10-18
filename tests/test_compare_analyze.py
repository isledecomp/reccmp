from unittest.mock import Mock, patch
import pytest
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.types import EntityType, ImageId
from reccmp.isledecomp.compare.analyze import (
    create_analysis_floats,
    create_analysis_strings,
    create_thunks,
)


@pytest.fixture(name="db")
def fixture_db():
    return EntityDb()


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
    assert e.get("type") == EntityType.FUNCTION
    assert e.get("size") == 5
    assert e.get("ref_orig") == 200


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
