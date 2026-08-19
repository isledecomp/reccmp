"""Tests for parsing the overall structure of cvdump text: how the output
splits into sections, and the flags derived from section content — here, the
16-bit type pool marker that decides the symbol truncation policy."""

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
    """A TYPES section that opens with the 16-bit conversion message marks an
    MSVC 4.x-era PDB, whose symbol names are truncated at 255 characters. Both
    the parser flag and the derived truncation policy must reflect that."""
    parser = CvdumpParser()
    parser.read_section("TYPES", TYPES_16BIT)

    assert parser.is_16bit_type_pool is True
    assert CvdumpAnalysis(parser).truncate_symbols is True


def test_32bit_type_pool_does_not_truncate():
    """A TYPES section without the 16-bit conversion message means the type
    pool is already 32-bit and symbol names are not truncated at 255
    characters. Truncating them anyway would make distinct long symbols
    collide and produce arbitrary non-unique matches."""
    parser = CvdumpParser()
    parser.read_section("TYPES", TYPES_32BIT)

    assert parser.is_16bit_type_pool is False
    assert CvdumpAnalysis(parser).truncate_symbols is False


def test_no_types_section_assumes_truncation():
    """Cvdump output with no TYPES section carries no evidence about the type
    pool either way, so the parser reports None and the analysis falls back to
    truncating symbol names — the historical behavior."""
    parser = CvdumpParser()

    assert parser.is_16bit_type_pool is None
    assert CvdumpAnalysis(parser).truncate_symbols is True


def test_converting_message_does_not_split_a_new_section():
    """The 16-bit conversion message begins with three asterisks, just like a
    section header. It must not start a new section: iter_cvdump_sections has
    to keep it inside the body of the TYPES section, both so the split into
    sections stays correct and so the parser can see the message at all."""
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
