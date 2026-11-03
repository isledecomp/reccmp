"""Tests matching of string literals that have no symbol in the recomp,
and the lookup of the object file data for a source file."""

from pathlib import PurePath, PureWindowsPath
from textwrap import dedent
from unittest.mock import Mock, ANY
import pytest
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb
from reccmp.compare.event import ReccmpEvent, ReccmpReportProtocol
from reccmp.compare.lines import LinesDb
from reccmp.compare.match_msvc import match_strings, match_unpooled_strings
from reccmp.compare.objects import ObjectDataRegions
from reccmp.cvdump import CvdumpAnalysis, CvdumpParser
from reccmp.formats import PEImage
from reccmp.formats.image import ImageRegion
from .raw_image import RawImage

ORIG_BASE = 0x1000
RECOMP_BASE = 0x5000


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


@pytest.fixture(name="report")
def fixture_report_mock() -> ReccmpReportProtocol:
    return Mock(spec=ReccmpReportProtocol)


def add_orig_string(db: EntityDb, addr: int, text: bytes, filename: str):
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            addr,
            type=EntityType.STRING,
            name=f'"{text.decode()}"',
            filename=filename,
            size=len(text) + 1,
            verified=True,
        )


def regions(lookup: dict[str, list[range]]):
    return lambda filename: lookup.get(filename, [])


def test_match_in_own_object(db):
    """The same text in two files: each annotation matches the copy in its own object."""
    orig = RawImage.from_memory(b"hello\0\0\0hello\0\0\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"hello\0\0\0hello\0\0\0", base_addr=RECOMP_BASE)

    # Orig order is b.cpp then a.cpp, recomp order is a.cpp then b.cpp.
    add_orig_string(db, ORIG_BASE, b"hello", "b.cpp")
    add_orig_string(db, ORIG_BASE + 8, b"hello", "a.cpp")

    lookup = {
        "a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 8)],
        "b.cpp": [range(RECOMP_BASE + 8, RECOMP_BASE + 16)],
    }
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE + 8
    assert db.get(ImageId.ORIG, ORIG_BASE + 8).recomp_addr == RECOMP_BASE

    # The new recomp entity is a string with the text and size of the orig string.
    ent = db.get(ImageId.RECOMP, RECOMP_BASE)
    assert ent.get("type") == EntityType.STRING
    assert ent.name == '"hello"'
    assert ent.size(ImageId.RECOMP) == 6


def test_no_region_no_match(db, report):
    """Without a region for the file there is no match and no report.
    The string is left for match_strings."""
    orig = RawImage.from_memory(b"hello\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"hello\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE, b"hello", "a.cpp")

    match_unpooled_strings(db, orig, recomp, regions({}))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr is None

    match_strings(db, report)
    report.assert_called_with(ReccmpEvent.NO_MATCH, ORIG_BASE, msg=ANY)


def test_existing_entity_is_not_a_candidate(db):
    """A recomp address that has an entity (a string with a symbol,
    or a char array variable) is not matched here."""
    orig = RawImage.from_memory(b"hello\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"hello\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE, b"hello", "a.cpp")

    with db.batch() as batch:
        batch.set(ImageId.RECOMP, RECOMP_BASE, type=EntityType.DATA, name="g_hello")

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 6)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr is None


def test_inside_existing_entity_is_not_a_candidate(db):
    """The text is the tail of a string that has an entity."""
    orig = RawImage.from_memory(b"lo\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"hello\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE, b"lo", "a.cpp")

    with db.batch() as batch:
        batch.set(ImageId.RECOMP, RECOMP_BASE, type=EntityType.STRING, size=6)

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 6)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr is None


def test_prefer_start_of_literal(db):
    """The text is also the tail of a longer string.
    Match the hit that follows a null terminator."""
    orig = RawImage.from_memory(b"lo\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"hello\0\0\0lo\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE, b"lo", "a.cpp")

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 11)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE + 8

    # No entity for the tail of the longer string.
    assert db.get(ImageId.RECOMP, RECOMP_BASE + 3) is None


def test_only_hit_inside_other_data_is_not_matched(db):
    """The only hit is not at the start of a literal (here: inside a table).
    No match and no entity: the string is left for match_strings."""
    orig = RawImage.from_memory(b"a\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"\x01\x02\x03a\0\0\0\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE, b"a", "a.cpp")

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 8)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr is None
    assert db.get(ImageId.RECOMP, RECOMP_BASE + 3) is None


def test_literal_after_entity(db):
    """A literal that follows an entity whose last byte is not null,
    such as a float constant."""
    orig = RawImage.from_memory(b"hello\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"\0\0\x80\x3fhello\0\0\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE, b"hello", "a.cpp")

    with db.batch() as batch:
        batch.set(ImageId.RECOMP, RECOMP_BASE, type=EntityType.FLOAT, size=4)

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 12)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE + 4


def test_orig_alignment_does_not_matter(db):
    """Only the recomp literal has to be 4-byte aligned."""
    orig = RawImage.from_memory(b"\0hello\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"hello\0\0\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE + 1, b"hello", "a.cpp")

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 8)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE + 1).recomp_addr == RECOMP_BASE


def test_duplicates_in_one_file(db):
    """Two annotations and two copies in the same object match in address order."""
    orig = RawImage.from_memory(b"hello\0\0\0hello\0\0\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"hello\0\0\0hello\0\0\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE + 8, b"hello", "a.cpp")
    add_orig_string(db, ORIG_BASE, b"hello", "a.cpp")

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 16)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE
    assert db.get(ImageId.ORIG, ORIG_BASE + 8).recomp_addr == RECOMP_BASE + 8


def test_more_copies_than_annotations(db):
    """One annotation, two copies (one per use): match the first.
    The other copy is a string entity with the same name, but not matched."""
    orig = RawImage.from_memory(b"hello\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"hello\0\0\0hello\0\0\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE, b"hello", "a.cpp")

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 16)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE

    other = db.get(ImageId.RECOMP, RECOMP_BASE + 8)
    assert other.orig_addr is None
    assert other.get("type") == EntityType.STRING
    assert other.name == '"hello"'
    assert other.size(ImageId.RECOMP) == 6
    assert other.get("unpooled_copy") is True


def test_other_filenames(db):
    """A string annotated in two files matches the copy in the first file.
    The copy in the other file gets the same name."""
    orig = RawImage.from_memory(b"hello\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"hello\0\0\0hello\0\0\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE, b"hello", "a.cpp")
    with db.batch() as batch:
        batch.set(ImageId.ORIG, ORIG_BASE, other_filenames=["b.cpp"])

    lookup = {
        "a.cpp": [range(RECOMP_BASE + 8, RECOMP_BASE + 16)],
        "b.cpp": [range(RECOMP_BASE, RECOMP_BASE + 8)],
    }
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE + 8
    other = db.get(ImageId.RECOMP, RECOMP_BASE)
    assert other.orig_addr is None
    assert other.name == '"hello"'


def test_other_file_has_the_only_copy(db, report):
    """The annotating file has no region (its object file is unknown):
    the first copy in another annotating file is the match, the second
    is named only."""
    orig = RawImage.from_memory(b"hello\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"hello\0\0\0hello\0\0\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE, b"hello", "tables.cpp")
    with db.batch() as batch:
        batch.set(ImageId.ORIG, ORIG_BASE, other_filenames=["b.cpp"])

    lookup = {"b.cpp": [range(RECOMP_BASE, RECOMP_BASE + 16)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))
    match_strings(db, report)

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE
    other = db.get(ImageId.RECOMP, RECOMP_BASE + 8)
    assert other.orig_addr is None
    assert other.name == '"hello"'
    report.assert_not_called()


def test_widechar(db):
    raw = "hi".encode("utf-16-le") + b"\0\0"
    orig = RawImage.from_memory(raw, base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"\0\0\0\0" + raw, base_addr=RECOMP_BASE)

    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            ORIG_BASE,
            type=EntityType.WIDECHAR,
            name='L"hi"',
            filename="a.cpp",
            size=len(raw),
        )

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 4 + len(raw))]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE + 4
    copy = db.get(ImageId.RECOMP, RECOMP_BASE + 4)
    assert copy.get("type") == EntityType.WIDECHAR
    assert copy.size(ImageId.RECOMP) == len(raw)


def test_widechar_tail_is_not_a_literal(db):
    """The high byte of the character before the tail is null.
    That does not make the tail a literal of its own."""
    raw = "1".encode("utf-16-le") + b"\0\0"
    longer = "ab1".encode("utf-16-le") + b"\0\0"
    orig = RawImage.from_memory(raw, base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(longer + raw, base_addr=RECOMP_BASE)

    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            ORIG_BASE,
            type=EntityType.WIDECHAR,
            name='L"1"',
            filename="a.cpp",
            size=len(raw),
        )

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 12)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE + 8
    assert db.get(ImageId.RECOMP, RECOMP_BASE + 4) is None


def test_widechar_after_narrow_literal_from_same_pass(db):
    """A narrow literal of 3 bytes plus terminator needs no padding, so the
    byte before the wide literal is not null. The narrow literal is matched
    in the same pass, so it is not in the database yet."""
    wide = "x".encode("utf-16-le") + b"\0\0"
    orig = RawImage.from_memory(b"abc\0" + wide, base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"abc\0" + wide, base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE, b"abc", "a.cpp")

    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            ORIG_BASE + 4,
            type=EntityType.WIDECHAR,
            name='L"x"',
            filename="a.cpp",
            size=len(wide),
        )

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 8)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE
    assert db.get(ImageId.ORIG, ORIG_BASE + 4).recomp_addr == RECOMP_BASE + 4


def test_tail_of_string_from_same_pass(db):
    """No match with the tail of a longer string that is matched in the same pass."""
    orig = RawImage.from_memory(b"hello\0\0\0lo\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"hello\0", base_addr=RECOMP_BASE)
    add_orig_string(db, ORIG_BASE + 8, b"lo", "a.cpp")
    add_orig_string(db, ORIG_BASE, b"hello", "a.cpp")

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 6)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE
    assert db.get(ImageId.ORIG, ORIG_BASE + 8).recomp_addr is None


def test_copy_is_not_matched_by_text(db):
    """An unmatched copy in one object file is not a match for the
    annotation in another file. That one matches the string with a symbol."""
    orig = RawImage.from_memory(b"hello\0\0\0hello\0\0\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(
        b"hello\0\0\0hello\0\0\0hello\0\0\0", base_addr=RECOMP_BASE
    )
    add_orig_string(db, ORIG_BASE, b"hello", "pooled.cpp")
    add_orig_string(db, ORIG_BASE + 8, b"hello", "unpooled.cpp")

    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            RECOMP_BASE + 16,
            type=EntityType.STRING,
            name='"hello"',
            size=6,
        )

    lookup = {"unpooled.cpp": [range(RECOMP_BASE, RECOMP_BASE + 16)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))
    match_strings(db)

    assert db.get(ImageId.ORIG, ORIG_BASE + 8).recomp_addr == RECOMP_BASE
    assert db.get(ImageId.RECOMP, RECOMP_BASE + 8).orig_addr is None
    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr == RECOMP_BASE + 16


def test_empty_string_skipped(db):
    orig = RawImage.from_memory(b"\0", base_addr=ORIG_BASE)
    recomp = RawImage.from_memory(b"\0\0\0\0", base_addr=RECOMP_BASE)

    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            ORIG_BASE,
            type=EntityType.STRING,
            name='""',
            filename="a.cpp",
            size=1,
        )

    lookup = {"a.cpp": [range(RECOMP_BASE, RECOMP_BASE + 4)]}
    match_unpooled_strings(db, orig, recomp, regions(lookup))

    assert db.get(ImageId.ORIG, ORIG_BASE).recomp_addr is None


#### ObjectDataRegions ####

CODE_START = 0x401000
DATA_START = 0x402000


@pytest.fixture(name="recomp_bin")
def fixture_recomp_bin():
    """Section 1 is code at 0x401000, section 2 is data at 0x402000."""
    binfile = Mock(spec=PEImage)
    binfile.is_valid_section.side_effect = lambda section: section in (1, 2)
    binfile.get_abs_addr.side_effect = (
        lambda section, offset: (CODE_START, DATA_START)[section - 1] + offset
    )
    binfile.get_data_regions.return_value = [ImageRegion(DATA_START, b"", 0x1000)]
    return binfile


@pytest.fixture(name="cvdump_analysis")
def fixture_cvdump_analysis() -> CvdumpAnalysis:
    parser = CvdumpParser()
    parser.read_section(
        "MODULES",
        dedent("""\
        0001 "a.obj"
        0002 "CMakeFiles/game.dir/src/b.cpp.obj"
        0003 "tables.obj"
        0004 "strings_c.obj"
        0005 "dup.obj"
        0006 "lib/dup.obj"
        0007 "vendor.lib" "strings.obj"
        0008 "game.lib" "code.obj"
        0009 "game.lib" "tables2.obj"
        """),
    )
    parser.read_section(
        "SECTION CONTRIBUTIONS",
        dedent("""\
          0001  0001:00000000  00000100  60501020
          0002  0001:00000100  00000100  60501020
          0001  0002:00000000  00000020  C0300040
          0002  0002:00000020  00000030  C0300040
          0003  0002:00000050  00000010  C0300040
          0003  0005:00000000  00000010  C0300040
          0004  0002:00000060  00000010  C0300040
          0005  0002:00000070  00000010  C0300040
          0006  0002:00000080  00000010  C0300040
          0007  0002:00000090  00000010  C0300040
          0008  0001:00000200  00000100  60501020
          0009  0002:000000a0  00000010  C0300040
        """),
    )
    return CvdumpAnalysis(parser)


def test_regions_by_line_numbers(cvdump_analysis, recomp_bin):
    """Line numbers of the file lead to the module and its data."""
    a_path = PurePath("src/a.cpp")
    b_path = PurePath("src/b.cpp")
    lines_db = LinesDb()
    lines_db.add_local_paths([a_path, b_path])
    lines_db.add_line(PureWindowsPath("src\\a.cpp"), 10, CODE_START + 0x40)
    lines_db.add_line(PureWindowsPath("src\\b.cpp"), 10, CODE_START + 0x140)

    object_regions = ObjectDataRegions(cvdump_analysis, lines_db, recomp_bin)

    assert object_regions.get(a_path) == [range(DATA_START, DATA_START + 0x20)]
    assert object_regions.get(str(b_path)) == [
        range(DATA_START + 0x20, DATA_START + 0x50)
    ]


def test_regions_header_in_two_modules(cvdump_analysis, recomp_bin):
    path = PurePath("src/inline.h")
    lines_db = LinesDb()
    lines_db.add_local_paths([path])
    lines_db.add_line(PureWindowsPath("src\\inline.h"), 10, CODE_START + 0x40)
    lines_db.add_line(PureWindowsPath("src\\inline.h"), 10, CODE_START + 0x140)

    object_regions = ObjectDataRegions(cvdump_analysis, lines_db, recomp_bin)

    assert object_regions.get(path) == [
        range(DATA_START, DATA_START + 0x20),
        range(DATA_START + 0x20, DATA_START + 0x50),
    ]


def test_regions_by_object_name(cvdump_analysis, recomp_bin):
    """A file without line numbers is found by the name of its object file."""
    object_regions = ObjectDataRegions(cvdump_analysis, LinesDb(), recomp_bin)

    # The contribution in the invalid section 5 is ignored.
    assert object_regions.get(PurePath("src/tables.cpp")) == [
        range(DATA_START + 0x50, DATA_START + 0x60)
    ]
    assert object_regions.get(PurePath("src/b.cpp")) == [
        range(DATA_START + 0x20, DATA_START + 0x50)
    ]
    assert object_regions.get(PurePath("src/strings.c")) == [
        range(DATA_START + 0x60, DATA_START + 0x70)
    ]
    assert not object_regions.get(PurePath("src/unknown.cpp"))

    # Two object files with this name
    assert not object_regions.get(PurePath("src/dup.cpp"))

    # An object from a library is not a candidate, even with a unique name.
    assert not object_regions.get(PurePath("src/strings.cpp"))


def test_regions_by_object_name_in_project_library(cvdump_analysis, recomp_bin):
    """A library is part of the project if one of its modules has line
    numbers for a local file. The data-only object in it is then found
    by name, while the object in the vendor library is still not."""
    code_path = PurePath("src/code.cpp")
    lines_db = LinesDb()
    lines_db.add_local_paths([code_path])
    lines_db.add_line(PureWindowsPath("src\\code.cpp"), 10, CODE_START + 0x240)

    object_regions = ObjectDataRegions(cvdump_analysis, lines_db, recomp_bin)

    assert object_regions.get(PurePath("src/tables2.cpp")) == [
        range(DATA_START + 0xA0, DATA_START + 0xB0)
    ]
    assert not object_regions.get(PurePath("src/strings.cpp"))
