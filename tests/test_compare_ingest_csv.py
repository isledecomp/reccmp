from textwrap import dedent
from pathlib import PurePath, PureWindowsPath
import pytest
from reccmp.compare.db import EntityDb
from reccmp.compare.ingest import load_csv, load_data_sources
from reccmp.compare.lines import LinesDb
from reccmp.compare.match_msvc import (
    match_functions,
    match_functions_by_file,
    match_symbols,
)
from reccmp.types import EntityType, ImageId
from reccmp.formats import TextFile


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


def test_load_data_sources(db: EntityDb):
    """Should create an entity by parsing the CSV."""
    ds_files = (
        TextFile(
            PurePath("test.csv"),
            dedent("""\
                address,name
                0x1234,hello
            """),
        ),
    )

    load_data_sources(db, ds_files)

    entity = db.get(ImageId.ORIG, 0x1234)
    assert entity is not None
    assert entity.get("name") == "hello"


def test_load_data_sources_skip_unknown(db: EntityDb):
    """Should skip files we cannot parse and create entities from the rest."""
    ds_files = (
        TextFile(
            PurePath("test.txt"),
            dedent("""\
                address,name
                0x5555,hello
            """),
        ),
        TextFile(
            PurePath("test.csv"),
            dedent("""\
                address,name
                0x1234,hello
            """),
        ),
    )

    load_data_sources(db, ds_files)

    entity = db.get(ImageId.ORIG, 0x1234)
    assert entity is not None
    assert entity.get("name") == "hello"

    assert db.get(ImageId.ORIG, 0x5555) is None


def test_load_csv(db: EntityDb):
    """Should create an entity by parsing the CSV."""
    csv_file = TextFile(
        PurePath("test.csv"),
        dedent("""\
            address,name
            0x1234,hello
        """),
    )

    load_csv(db, csv_file)

    entity = db.get(ImageId.ORIG, 0x1234)
    assert entity is not None
    assert entity.get("name") == "hello"


def test_csv_file_distinguishes_same_named_functions(db: EntityDb):
    """Distinguish same-named functions by file."""
    lines = LinesDb()
    lines.add_local_paths(
        [PurePath(f"project/vendor/{name}.c") for name in ("one", "two", "three")]
    )
    lines.add_line(PureWindowsPath("C:/src/one.c"), 10, 0x5000)
    lines.add_line(PureWindowsPath("C:/src/two.c"), 20, 0x6000)
    lines.add_line(PureWindowsPath("C:/src/three.c"), 30, 0x7000)
    lines.mark_function_starts((0x5000, 0x6000, 0x7000))

    with db.batch() as batch:
        batch.set(ImageId.RECOMP, 0x5000, type=EntityType.FUNCTION, name="helper")
        batch.set(ImageId.RECOMP, 0x6000, type=EntityType.FUNCTION, name="helper")
        batch.set(
            ImageId.RECOMP,
            0x7000,
            type=EntityType.FUNCTION,
            name="other",
            symbol="unique_other",
        )

    load_csv(
        db,
        TextFile(
            PurePath("test.csv"),
            dedent("""\
                address,type,name,file,symbol
                0x1000,function,helper,two.c,
                0x2000,function,helper,vendor/one.c,
                0x3000,function,different_name,three.c,unique_other
            """),
        ),
    )
    match_functions_by_file(db, lines)

    assert db.get(ImageId.ORIG, 0x1000).recomp_addr == 0x6000
    assert db.get(ImageId.ORIG, 0x2000).recomp_addr == 0x5000
    assert db.get(ImageId.ORIG, 0x3000).recomp_addr == 0x7000


def test_csv_file_constrains_symbol_and_name_matching(db: EntityDb):
    """An incorrect file cannot match, but name can follow a failed symbol lookup."""
    lines = LinesDb()
    lines.add_local_paths(
        [PurePath("project/one/common.c"), PurePath("project/two/common.c")]
    )
    lines.add_line(PureWindowsPath("C:/one/common.c"), 10, 0x5000)
    lines.add_line(PureWindowsPath("C:/two/common.c"), 20, 0x6000)
    lines.mark_function_starts((0x5000, 0x6000))

    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            0x5000,
            type=EntityType.FUNCTION,
            name="helper",
            symbol="unique_helper",
        )
        batch.set(ImageId.RECOMP, 0x6000, type=EntityType.FUNCTION, name="helper")

    load_csv(
        db,
        TextFile(
            PurePath("test.csv"),
            dedent("""\
                address,type,name,file,symbol
                0x1000,function,helper,common.c,
                0x2000,function,helper,missing.c,unique_helper
                0x3000,function,helper,one/common.c,wrong_symbol
            """),
        ),
    )
    match_symbols(db)
    match_functions_by_file(db, lines)
    match_functions(db)

    assert db.get(ImageId.ORIG, 0x1000).recomp_addr is None
    assert db.get(ImageId.ORIG, 0x2000).recomp_addr is None
    assert db.get(ImageId.ORIG, 0x3000).recomp_addr == 0x5000


def test_load_csv_overwrite(db: EntityDb):
    """Should overwrite (additively) if the same address is used in multiple CSV files."""
    csv_files = (
        TextFile(
            PurePath("test.csv"),
            dedent("""\
                address,name,type
                0x1234,hello,function
                0x5555,pizza,function
                0x5555,jetski,global
            """),
        ),
        TextFile(
            PurePath("zzzz.csv"),
            dedent("""\
                address,name
                0x1234,test
            """),
        ),
    )

    for csv_file in csv_files:
        load_csv(db, csv_file)

    # Name overwritten by second file. Type retained from first file.
    entity = db.get(ImageId.ORIG, 0x1234)
    assert entity is not None
    assert entity.get("name") == "test"
    assert entity.get("type") == EntityType.FUNCTION

    # Both fields overwritten in the same file.
    entity = db.get(ImageId.ORIG, 0x5555)
    assert entity is not None
    assert entity.get("name") == "jetski"
    assert entity.get("type") == EntityType.DATA


def test_load_csv_with_errors(db: EntityDb):
    """Should skip lines with a syntax error and create entities for the rest."""
    # codespell:ignore-begin
    csv_file = TextFile(
        PurePath("test.csv"),
        dedent("""\
            address|type
            5555|libary
            1234|function
            zzzz|function
            4321|template
            """),
    )
    # codespell:ignore-end

    load_csv(db, csv_file)

    entity = db.get(ImageId.ORIG, 0x1234)
    assert entity is not None
    assert entity.get("type") == EntityType.FUNCTION

    entity = db.get(ImageId.ORIG, 0x4321)
    assert entity is not None
    assert entity.get("type") == EntityType.FUNCTION

    assert db.get(ImageId.ORIG, 0x5555) is None


def test_load_csv_with_fatal_error(db: EntityDb):
    """Should not create entities from a CSV with a fatal parsing error."""
    csv_file = TextFile(
        PurePath("test.csv"),
        dedent("""\
            address|name|name
            1234|test|test
            4321|hello|hello
            """),
    )

    load_csv(db, csv_file)

    assert db.get(ImageId.ORIG, 0x1234) is None
    assert db.get(ImageId.ORIG, 0x4321) is None
