"""Test Cvdump SYMBOLS parser, reading function stack/params"""

from reccmp.cvdump.symbols import CvdumpSymbolsParser

PROC_WITH_BLOC = """
(000638) S_GPROC32: [0001:000C6135], Cb: 00000361, Type:             0x10ED, RegistrationBook::ReadyWorld
         Parent: 00000000, End: 00000760, Next: 00000000
         Debug start: 0000000C, Debug end: 0000035C
         Flags: Frame Ptr Present
(00067C)  S_BPREL32: [FFFFFFD0], Type:             0x10EC, this
(000690)  S_BPREL32: [FFFFFFDC], Type:             0x10F5, checkmarkBuffer
(0006AC)  S_BPREL32: [FFFFFFE8], Type:             0x10F6, letterBuffer
(0006C8)  S_BPREL32: [FFFFFFF4], Type:      T_SHORT(0011), i
(0006D8)  S_BPREL32: [FFFFFFF8], Type:             0x10F8, players
(0006EC)  S_BPREL32: [FFFFFFFC], Type:             0x1044, gameState
(000704)  S_BLOCK32: [0001:000C624F], Cb: 000001DA,
          Parent: 00000638, End: 0000072C
(00071C)   S_BPREL32: [FFFFFFD8], Type:      T_SHORT(0011), j
(00072C)  S_END
(000730)  S_BLOCK32: [0001:000C6448], Cb: 00000032,
          Parent: 00000638, End: 0000075C
(000748)   S_BPREL32: [FFFFFFD4], Type:             0x10FA, infoman
(00075C)  S_END
(000760) S_END
"""


def test_sblock32():
    """S_END has double duty as marking the end of a function (S_GPROC32)
    and a scope block (S_BLOCK32). Make sure we can distinguish between
    the two and not end a function early."""
    parser = CvdumpSymbolsParser()
    for line in PROC_WITH_BLOC.split("\n"):
        parser.read_line(line)

    # Make sure we can read the proc and all its stack references
    assert len(parser.symbols) == 1
    assert len(parser.symbols[0].stack_symbols) == 8


LOCAL_PROC = """
(0000A4) S_LPROC32: [0001:00000180], Cb: 0000002F, Type:             0x1078, check_watchlist
         Parent: 00000000, End: 000000EC, Next: 00000000
         Debug start: 00000000, Debug end: 0000002E

(0000DC)  S_REGISTER: esi, Type:    T_32PVOID(0403), ptr

(0000EC) S_END
"""


def test_local_proc():
    """S_LPROC32 blocks should be proccessed as well, since these functions
    may use different calling conventions from S_GPROC32 functions."""
    parser = CvdumpSymbolsParser()
    for line in LOCAL_PROC.split("\n"):
        parser.read_line(line)

    # Make sure we can read the proc
    assert len(parser.symbols) == 1


LDATA32_INSIDE_FUNCTION = """\
(004368) S_GPROC32: [0001:00050A28], Cb: 000000B5, Type:             0x1010, GetCDPathFromPathsTxtFile

(0043AC)  S_BPREL32: [00000008], Type:   T_32PRCHAR(0470), pPath_name
(0043C4)  S_LDATA32: [0003:0000B3C4], Type:       T_INT4(0074), got_it_already
(0043E4)  S_LDATA32: [0003:0003C488], Type:             0x100B, cd_pathname

(004400) S_END
"""


def test_ldata32_inside_function():
    """S_LDATA32 leaves inside of a function (S_GPROC32) are assumed to be
    static variables from that function."""
    parser = CvdumpSymbolsParser()
    for line in LDATA32_INSIDE_FUNCTION.split("\n"):
        parser.read_line(line)

    assert len(parser.symbols) == 1
    assert len(parser.symbols[0].static_variables) == 2
    assert [v.name for v in parser.symbols[0].static_variables] == [
        "got_it_already",
        "cd_pathname",
    ]


def test_ldata32_outside_function():
    """Should ignore an S_LDATA32 leaf found outside a function.
    These appear to indicate const global variables and they should be
    repeated in the GLOBALS section."""
    parser = CvdumpSymbolsParser()
    parser.read_line(
        "(00045C) S_LDATA32: [0003:0000E298], Type:             0x1060, TestVariable"
    )

    # ignored... for now.
    # Should not crash with a failed assert. See GH issue #183.
    assert len(parser.symbols) == 0
