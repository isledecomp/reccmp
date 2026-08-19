"""Detecting whether a PDB truncates symbol names to 255 characters.
This is a quirk of MSVC 4.x-era PDBs, which cvdump announces by converting
the 16-bit type pool at the top of the TYPES section."""

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
    """An MSVC 4.x-era PDB truncates symbol names."""
    parser = CvdumpParser()
    parser.read_section("TYPES", TYPES_16BIT)

    assert parser.is_16bit_type_pool is True
    assert CvdumpAnalysis(parser).truncate_symbols is True


def test_32bit_type_pool_does_not_truncate():
    """A later toolchain does not, so truncating there would make distinct
    long symbols collide."""
    parser = CvdumpParser()
    parser.read_section("TYPES", TYPES_32BIT)

    assert parser.is_16bit_type_pool is False
    assert CvdumpAnalysis(parser).truncate_symbols is False


def test_no_types_section_assumes_truncation():
    """Without the TYPES section we cannot tell, so keep the historical
    behavior rather than guess."""
    parser = CvdumpParser()

    assert parser.is_16bit_type_pool is None
    assert CvdumpAnalysis(parser).truncate_symbols is True


def test_message_belongs_to_the_types_section():
    """The message begins with three asterisks like a section header does, but
    it is not one. It must land in the body of the TYPES section so that the
    parser can see it."""
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
