from textwrap import dedent
from pathlib import PurePath
import pytest
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.compare.ingest import load_csv, load_data_sources
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.formats import TextFile


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


def test_load_data_sources(db: EntityDb):
    """Should create an entity by parsing the CSV."""
    ds_files = (
        TextFile(
            PurePath("test.csv"),
            dedent(
                """\
                address,name
                0x1234,hello
            """
            ),
        ),
    )

    load_data_sources(db, ds_files)

    entity = db.get_by_orig(0x1234)
    assert entity is not None
    assert entity.get("name") == "hello"


def test_load_data_sources_skip_unknown(db: EntityDb):
    """Should skip files we cannot parse and create entities from the rest."""
    ds_files = (
        TextFile(
            PurePath("test.txt"),
            dedent(
                """\
                address,name
                0x5555,hello
            """
            ),
        ),
        TextFile(
            PurePath("test.csv"),
            dedent(
                """\
                address,name
                0x1234,hello
            """
            ),
        ),
    )

    load_data_sources(db, ds_files)

    entity = db.get_by_orig(0x1234)
    assert entity is not None
    assert entity.get("name") == "hello"

    assert db.get_by_orig(0x5555) is None


def test_load_csv(db: EntityDb):
    """Should create an entity by parsing the CSV."""
    csv_file = TextFile(
        PurePath("test.csv"),
        dedent(
            """\
            address,name
            0x1234,hello
        """
        ),
    )

    load_csv(db, csv_file)

    entity = db.get_by_orig(0x1234)
    assert entity is not None
    assert entity.get("name") == "hello"


def test_load_csv_overwrite(db: EntityDb):
    """Should overwrite (additively) if the same address is used in multiple CSV files."""
    csv_files = (
        TextFile(
            PurePath("test.csv"),
            dedent(
                """\
                address,name,type
                0x1234,hello,function
                0x5555,pizza,function
                0x5555,jetski,global
            """
            ),
        ),
        TextFile(
            PurePath("zzzz.csv"),
            dedent(
                """\
                address,name
                0x1234,test
            """
            ),
        ),
    )

    for csv_file in csv_files:
        load_csv(db, csv_file)

    # Name overwritten by second file. Type retained from first file.
    entity = db.get_by_orig(0x1234)
    assert entity is not None
    assert entity.get("name") == "test"
    assert entity.get("type") == EntityType.FUNCTION

    # Both fields overwritten in the same file.
    entity = db.get_by_orig(0x5555)
    assert entity is not None
    assert entity.get("name") == "jetski"
    assert entity.get("type") == EntityType.DATA


def test_load_csv_with_errors(db: EntityDb):
    """Should skip lines with a syntax error and create entities for the rest."""
    csv_file = TextFile(
        PurePath("test.csv"),
        dedent(
            """\
            address|type
            5555|libary
            1234|function
            zzzz|function
            4321|template
            """
        ),
    )

    load_csv(db, csv_file)

    entity = db.get_by_orig(0x1234)
    assert entity is not None
    assert entity.get("type") == EntityType.FUNCTION

    entity = db.get_by_orig(0x4321)
    assert entity is not None
    assert entity.get("type") == EntityType.FUNCTION

    assert db.get_by_orig(0x5555) is None


def test_load_csv_with_fatal_error(db: EntityDb):
    """Should not create entities from a CSV with a fatal parsing error."""
    csv_file = TextFile(
        PurePath("test.csv"),
        dedent(
            """\
            address|name|name
            1234|test|test
            4321|hello|hello
            """
        ),
    )

    load_csv(db, csv_file)

    assert db.get_by_orig(0x1234) is None
    assert db.get_by_orig(0x4321) is None
