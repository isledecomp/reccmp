"""Tests for creating/matching entities using code annotations."""

from textwrap import dedent
from pathlib import PurePath, Path, PureWindowsPath
import pytest
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.formats import PEImage
from reccmp.isledecomp.compare.ingest import load_markers
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.compare.lines import LinesDb


SampleFilesType = tuple[tuple[PurePath, str], ...]


@pytest.fixture(name="db")
def fixture_db():
    return EntityDb()


@pytest.fixture(name="lines_db")
def fixture_lines_db():
    return LinesDb()


def create_test_files(code_dir: Path, files: SampleFilesType):
    """Helper to establish the given code files in the base directory. (pytest tmp_path fixture)
    This is needed while DecompCodebase still depends on the filesystem."""
    for path, text in files:
        file_path = code_dir / path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with file_path.open("w+") as f:
            f.write(text)


def test_load_code_invalid_addr(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Should not create entity for an invalid address."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                // FUNCTION: TEST 0x11001000"
                void test() { }
            """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    # No exception raised
    assert db.get_by_orig(0x11001000) is None


def test_load_code_duplicate_addr(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Each address can only be used once.
    Files are loaded in the order returned by os.walk.
    Create the entity from the annotation that appears first."""
    files = (
        (
            PurePath("test.h"),
            dedent(
                """\
                // FUNCTION: TEST 0x1001dde0
                // _Lockit::~_Lockit
                """
            ),
        ),
        (
            PurePath("zzz.h"),
            dedent(
                """\
                // FUNCTION: TEST 0x1001dde0
                // Hello
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    # Should use the name from the first file (alphabetical, by path)
    entity = db.get_by_orig(0x1001DDE0)
    assert entity is not None
    assert entity.get("name") == "_Lockit::~_Lockit"


def test_load_code_cpp_symbol_function(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Function namerefs that begin with '?' are assumed to refer to the entity symbol."""
    files = (
        (
            PurePath("test.h"),
            dedent(
                """\
                // LIBRARY: TEST 0x10086240
                // ??2@YAPAXI@Z"""
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x10086240)
    assert entity is not None
    assert entity.get("symbol") == "??2@YAPAXI@Z"
    assert entity.get("name") is None


@pytest.mark.xfail(reason="Potential future enhancement.")
def test_load_code_cpp_symbol_global(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Global namerefs that begin with '?' are assumed to refer to the entity symbol."""
    files = (
        (
            PurePath("test.h"),
            dedent(
                """\
                // GLOBAL: TEST 0x100fd624
                // ?__pInconsistency@@3P6AXXZA
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x100FD624)
    assert entity is not None
    assert entity.get("symbol") == "?__pInconsistency@@3P6AXXZA"
    assert entity.get("name") is None


def test_load_code_c_symbol_implicit(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Namerefs that begin with '_' are NOT assumed to be the symbol.
    This would cause problems for (e.g.) STL entities like '_Tree...'"""
    files = (
        (
            PurePath("test.h"),
            dedent(
                """\
                // LIBRARY: TEST 0x1008c410
                // _strlwr
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x1008C410)
    assert entity is not None
    assert entity.get("symbol") is None
    assert entity.get("name") == "_strlwr"


def test_load_code_c_symbol_explicit(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """If the SYMBOL annotation modifier is used, set the entity symbol instead of the name."""
    files = (
        (
            PurePath("test.h"),
            dedent(
                """\
                // LIBRARY: TEST 0x1008c410 SYMBOL
                // _strlwr
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x1008C410)
    assert entity is not None
    assert entity.get("symbol") == "_strlwr"
    assert entity.get("name") is None


def test_load_code_function_nameref_variants(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Should set extra properties for STUB and LIBRARY annotations."""
    files = (
        (
            PurePath("test.h"),
            dedent(
                """\
                // FUNCTION: TEST 0x1001dde0
                // _Lockit::~_Lockit

                // TEMPLATE: TEST 0x1001c050
                // Vector<unsigned char *>::~Vector<unsigned char *>

                // LIBRARY: TEST 0x1008b400
                // _atol
                
                // STUB: TEST 0x1008b4b0
                // _atoi

                // SYNTHETIC: TEST 0x100380e0
                // Pizza::`scalar deleting destructor'
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    # n.b. These fields are always set.
    # We don't need to protect against None by using: entity.get("stub", False)

    # FUNCTION
    entity = db.get_by_orig(0x1001DDE0)
    assert entity is not None
    assert entity.get("type") == EntityType.FUNCTION
    assert entity.get("library") is False
    assert entity.get("stub") is False
    assert entity.get("name") == "_Lockit::~_Lockit"

    # TEMPLATE
    entity = db.get_by_orig(0x1001C050)
    assert entity is not None
    assert entity.get("type") == EntityType.FUNCTION
    assert entity.get("library") is False
    assert entity.get("stub") is False
    assert entity.get("name") == "Vector<unsigned char *>::~Vector<unsigned char *>"

    # LIBRARY
    entity = db.get_by_orig(0x1008B400)
    assert entity is not None
    assert entity.get("type") == EntityType.FUNCTION
    assert entity.get("library") is True
    assert entity.get("stub") is False
    assert entity.get("name") == "_atol"

    # STUB
    entity = db.get_by_orig(0x1008B4B0)
    assert entity is not None
    assert entity.get("type") == EntityType.FUNCTION
    assert entity.get("library") is False
    assert entity.get("stub") is True
    assert entity.get("name") == "_atoi"

    # SYNTHETIC
    entity = db.get_by_orig(0x100380E0)
    assert entity is not None
    assert entity.get("type") == EntityType.FUNCTION
    assert entity.get("library") is False
    assert entity.get("stub") is False
    assert entity.get("name") == "Pizza::`scalar deleting destructor'"


def test_load_code_lineref(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Should create a function entity for a line-based annotation."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                // FUNCTION: TEST 0x10038220
                void Pizza::Start()
                {
                }
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x10038220)
    assert entity is not None

    # Nothing in the lines database. No match.
    assert entity.recomp_addr is None
    assert entity.get("type") == EntityType.FUNCTION


def test_load_code_match_line(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Should match the function based on its file path and line number."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                // FUNCTION: TEST 0x10038220
                void Pizza::Start()
                {
                }
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)

    # Mock reading from PDB to set up the lines database.
    lines_db.add_line(PureWindowsPath("test.cpp"), 3, 0x1234)
    lines_db.mark_function_starts([0x1234])

    # TODO: For a successful match, the recomp entity must already exist.
    with db.batch() as batch:
        batch.set_recomp(0x1234)

    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x10038220)
    assert entity is not None
    assert entity.recomp_addr == 0x1234

    # Should assign FUNCTION type as directed by the annotation.
    # The recomp entity had no type.
    assert entity.get("type") == EntityType.FUNCTION


def test_load_code_no_match_line(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Don't match the function if the line number does not match."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                // FUNCTION: TEST 0x10038220
                void Pizza::Start()
                {
                }
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)

    # Mock reading from PDB to set up the lines database.
    lines_db.add_line(PureWindowsPath("test.cpp"), 8, 0x1234)
    lines_db.mark_function_starts([0x1234])

    # TODO: For a successful match, the recomp entity must already exist.
    with db.batch() as batch:
        batch.set_recomp(0x1234)

    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x10038220)
    assert entity is not None
    assert entity.recomp_addr is None
    assert entity.get("type") == EntityType.FUNCTION


def test_load_code_string(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Should create a string entity from a STRING annotation."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                // STRING: TEST 0x100f038c
                char* pizza = "Pizza";
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x100F038C)
    assert entity is not None
    assert entity.get("type") == EntityType.STRING
    assert entity.get("size") == 6
    assert entity.get("name") == '"Pizza"'


def test_load_code_string_no_match(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Do not add the string entity if the text does not match the bytes at the address."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                // STRING: TEST 0x100f038c
                char* jetski = "Jetski";
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x100F038C)
    assert entity is None


def test_load_code_widechar(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Should create a widechar entity from a STRING annotation."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                // STRING: TEST 0x100daaa0
                char* nullstr = L"(null)";
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x100DAAA0)
    assert entity is not None
    assert entity.get("type") == EntityType.STRING
    assert entity.get("size") == 14
    assert entity.get("name") == 'L"(null)"'


def test_load_code_string_with_nulls(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Should read string with nulls included.
    Using the unicode string '(null)' from the above example."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                // STRING: TEST 0x100daaa0
                char* nullstr = "(\\x00n\\x00u\\x00l\\x00l\\x00)";
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x100DAAA0)
    assert entity is not None
    assert entity.get("type") == EntityType.STRING
    assert entity.get("size") == 12
    assert entity.get("name") == '"(\\x00n\\x00u\\x00l\\x00l\\x00)"'


def test_load_code_widechar_invalid(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Should not create entity if we cannot read a widechar.
    Decoding from this address throws a UnicodeDecodeError."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                // STRING: TEST 0x100dda7b
                char* test = L"test";
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x100DDA7B)
    assert entity is None


def test_load_code_vtable(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    files = (
        (
            PurePath("test.h"),
            dedent(
                """\
                // VTABLE: TEST 0x100d7380
                class Pizza {
                };
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x100D7380)
    assert entity is not None
    assert entity.get("type") == EntityType.VTABLE

    # Uses the class name as the entity name. We could add the `vftable' suffix.
    assert entity.get("name") == "Pizza"
    assert entity.get("base_class") is None


def test_load_code_vtable_vbase(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Should set base_class for VTABLE entities with virtual inheritance."""
    files = (
        (
            PurePath("test.h"),
            dedent(
                """\
                // VTABLE: TEST 0x100d9ec8 Lunch
                // VTABLE: TEST 0x100d7380 Pizza
                class Pizza : public Lunch {
                };
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x100D9EC8)
    assert entity is not None
    assert entity.get("type") == EntityType.VTABLE
    assert entity.get("name") == "Pizza"
    assert entity.get("base_class") == "Lunch"

    # Should assign the base class even if it is the same as the main class.
    entity = db.get_by_orig(0x100D7380)
    assert entity is not None
    assert entity.get("type") == EntityType.VTABLE
    assert entity.get("name") == "Pizza"
    assert entity.get("base_class") == "Pizza"


def test_load_code_variable(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                // GLOBAL: TEST 0x10102048
                const char* g_strACTION = "ACTION";
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x10102048)
    assert entity is not None
    assert entity.get("type") == EntityType.DATA
    assert entity.get("name") == "g_strACTION"


def test_load_code_static_variable(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Should create a static variable entity if the function is also annotated."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                // FUNCTION: TEST 0x1009da20
                void EnableResizing()
                {
                    // GLOBAL: TEST 0x10109594
                    static DWORD g_dwStyle;
                }
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x10109594)
    assert entity is not None
    assert entity.get("type") == EntityType.DATA
    assert entity.get("name") == "g_dwStyle"
    assert entity.get("static_var") is True
    assert entity.get("parent_function") == 0x1009DA20


@pytest.mark.xfail(reason="Creates regular global variable instead.")
def test_load_code_static_variable_no_function(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Will create static variable entity even if function is not annotated."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                void EnableResizing()
                {
                    // GLOBAL: TEST 0x10109594
                    static DWORD g_dwStyle;
                }
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x10109594)
    assert entity is not None
    assert entity.get("type") == EntityType.DATA
    assert entity.get("name") == "g_dwStyle"
    assert entity.get("static_var") is True


def test_load_code_line_marker(
    tmp_path: Path, db: EntityDb, lines_db: LinesDb, binfile: PEImage
):
    """Should create a LINE entity with the local file path and line number."""
    files = (
        (
            PurePath("test.cpp"),
            dedent(
                """\
                void Test()
                {
                    // LINE: TEST 0x10001038
                }
                """
            ),
        ),
    )
    create_test_files(tmp_path, files)
    load_markers(tmp_path, lines_db, binfile, "TEST", db)

    entity = db.get_by_orig(0x10001038)
    assert entity is not None
    assert entity.get("type") == EntityType.LINE
    assert entity.get("filename") == str(tmp_path / "test.cpp")
    assert entity.get("line") == 3
