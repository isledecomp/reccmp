"""Tests for splitting cvdump output into sections, and for the 16-bit
type pool marker that controls symbol truncation."""

from reccmp.cvdump.parser import CvdumpParser
from reccmp.cvdump.analysis import CvdumpAnalysis
from reccmp.cvdump.runner import iter_cvdump_sections

# The first lines of the TYPES section for an MSVC 4.x-era PDB.
TYPES_16BIT = """
*** Converting 16-bit types to 32-bit equivalents

0x1000 : Length = 6, Leaf = 0x1201 LF_ARGLIST argument count = 0
"""

# The same for a PDB whose type pool is already 32-bit.
TYPES_32BIT = """
0x1000 : Length = 6, Leaf = 0x1201 LF_ARGLIST argument count = 0
"""


def test_16bit_type_pool_truncates():
    """The 16-bit conversion message means this is an MSVC 4.x-era PDB,
    so symbol names are truncated at 255 characters."""
    parser = CvdumpParser()
    parser.read_section("TYPES", TYPES_16BIT)

    assert parser.is_16bit_type_pool is True
    assert CvdumpAnalysis(parser).truncate_symbols is True


def test_32bit_type_pool_does_not_truncate():
    """Without the conversion message, the type pool is 32-bit and symbol
    names are not truncated. Truncating anyway could make different long
    symbols collide and match incorrectly."""
    parser = CvdumpParser()
    parser.read_section("TYPES", TYPES_32BIT)

    assert parser.is_16bit_type_pool is False
    assert CvdumpAnalysis(parser).truncate_symbols is False


def test_no_types_section_assumes_truncation():
    """With no TYPES section we can't tell the PDB version. The parser
    reports None and the analysis assumes truncation, which matches the
    old behavior."""
    parser = CvdumpParser()

    assert parser.is_16bit_type_pool is None
    assert CvdumpAnalysis(parser).truncate_symbols is True


def test_converting_message_does_not_split_a_new_section():
    """The 16-bit conversion message starts with three asterisks, like a
    section header. iter_cvdump_sections should keep it inside the TYPES
    section body instead of starting a new section there, otherwise the
    parser never sees the message."""
    stdout = [
        "\n",
        "*** TYPES\n",
        "\n",
        "*** Converting 16-bit types to 32-bit equivalents\n",
        "\n",
        "0x1000 : Length = 6, Leaf = 0x1201 LF_ARGLIST argument count = 0\n",
        "\n",
        "*** SYMBOLS\n",
        "\n",
    ]

    sections = dict(iter_cvdump_sections(stdout))

    assert sorted(sections) == ["SYMBOLS", "TYPES"]
    assert "Converting 16-bit types" in sections["TYPES"]

    parser = CvdumpParser()
    for name, section in sections.items():
        parser.read_section(name, section)

    assert parser.is_16bit_type_pool is True
