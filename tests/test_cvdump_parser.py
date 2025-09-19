"""Test Cvdump parser, reading global variables"""

from reccmp.isledecomp.cvdump.parser import (
    CvdumpParser,
    GdataEntry,
)

GLOBALS_SAMPLE = """
S_PROCREF: 0x00000000: (   5, 000000D4) WinMain
S_LPROCREF: 0x00000000: (  21, 0000008C) write_char
S_GDATA32: [0003:00018F84], Type:      T_UINT4(0075), _winver
S_UDT:   T_32PRCHAR(0470), va_list
S_LDATA32: [0003:00018FCC], Type:       T_INT4(0074), fSystemSet
"""


def test_globals():
    """Ensure that CvdumpParser tracks symbols for global and link-local
    variables, while ignoring other symbol types found in the GLOBAL section"""
    parser = CvdumpParser()
    parser.read_section("GLOBALS", GLOBALS_SAMPLE)
    assert len(parser.globals) == 2

    assert parser.globals[0] == GdataEntry(
        section=0x0003,
        offset=0x00018F84,
        type="T_UINT4(0075)",
        name="_winver",
        is_global=True,
    )
    assert parser.globals[1] == GdataEntry(
        section=0x0003,
        offset=0x00018FCC,
        type="T_INT4(0074)",
        name="fSystemSet",
        is_global=False,
    )
