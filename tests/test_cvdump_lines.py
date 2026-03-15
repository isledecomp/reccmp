"""Testing the cvdump text parser: LINES section"""

from pathlib import PureWindowsPath
from reccmp.cvdump import CvdumpParser

SAMPLE_BASE = """\
** Module: "test.obj"

  C:\\path\\to\\flags.h (None), 0001:00078040-0007805E, line/addr pairs = 1

     58 00078040

  C:\\path\\to\\video.h (None), 0001:00078070-0007808C, line/addr pairs = 1

     25 00078070

"""


def test_basecase():
    """Should read line pairs from different files."""
    parser = CvdumpParser()
    parser.read_section("LINES", SAMPLE_BASE)

    flags_path = PureWindowsPath("C:\\path\\to\\flags.h")
    assert parser.lines[flags_path] == [(58, 1, 0x78040)]

    video_path = PureWindowsPath("C:\\path\\to\\video.h")
    assert parser.lines[video_path] == [(25, 1, 0x78070)]


SAMPLE_MULTILINE = """\
** Module: "test.obj"

  C:\\msvc420\\include\\list (None), 0001:00107CF0-00107DAC, line/addr pairs = 7

    224 00107CF0    225 00107D14    226 00107D41    227 00107D6E
    228 00107D83    229 00107D8F    230 00107D95
"""


def test_multiline():
    """Can read multiple lines from a single block."""
    parser = CvdumpParser()
    parser.read_section("LINES", SAMPLE_MULTILINE)

    path = PureWindowsPath("C:\\msvc420\\include\\list")
    assert parser.lines[path] == [
        (224, 1, 0x107CF0),
        (225, 1, 0x107D14),
        (226, 1, 0x107D41),
        (227, 1, 0x107D6E),
        (228, 1, 0x107D83),
        (229, 1, 0x107D8F),
        (230, 1, 0x107D95),
    ]


SAMPLE_MULTIPLE_BLOCKS = """\
** Module: "test.obj"

  Z:\\game\\jukeboxentity.h (None), 0001:00108930-0010894B, line/addr pairs = 3

     20 00108930     22 0010893C     23 00108946

  Z:\\game\\jukeboxentity.h (None), 0001:00108960-001089B6, line/addr pairs = 3

     27 00108960     28 0010896C     29 001089AF

"""


def test_multiple_blocks():
    """Should aggregate line pairs for the same source code file."""
    parser = CvdumpParser()
    parser.read_section("LINES", SAMPLE_MULTIPLE_BLOCKS)

    path = PureWindowsPath("Z:\\game\\jukeboxentity.h")
    assert parser.lines[path] == [
        (20, 1, 0x108930),
        (22, 1, 0x10893C),
        (23, 1, 0x108946),
        (27, 1, 0x108960),
        (28, 1, 0x10896C),
        (29, 1, 0x1089AF),
    ]


SAMPLE_PATH_SPACES = """\
** Module: "CMakeFiles\\beta10.dir\\Debug\\HELLO\\main.cpp.obj"

  C:\\decomp stuff\\historybook.cpp (None), 0001:000814B0-000814D4, line/addr pairs = 4

     95 000814B0     98 000814BB    100 000814C0    102 000814D0

"""


def test_path_with_spaces():
    """Should handle a Windows path with spaces."""
    parser = CvdumpParser()
    parser.read_section("LINES", SAMPLE_PATH_SPACES)

    path = PureWindowsPath("C:\\decomp stuff\\historybook.cpp")
    assert parser.lines[path] == [
        (95, 1, 0x814B0),
        (98, 1, 0x814BB),
        (100, 1, 0x814C0),
        (102, 1, 0x814D0),
    ]


SAMPLE_MD5 = """\
** Module: "test.obj"

  c:\\users\\test\\md5.cpp (MD5: 0123456789ABCDEF0123456789ABCDEF), 0001:000001C0-00000361, line/addr pairs = 19

     46 000001C0     48 000001D3     51 000001FF     53 0000020C
     54 00000220     57 00000227     58 0000023A     65 00000241
     66 00000255     67 00000277     68 00000293     71 000002AF
     73 000002C5     74 000002D7     76 000002F1     78 000002F3
     81 0000030F     88 0000031E     89 00000351
"""


def test_md5():
    """Should handle PDBs from newer MSVC that have a file checksum."""
    parser = CvdumpParser()
    parser.read_section("LINES", SAMPLE_MD5)

    path = PureWindowsPath("c:\\users\\test\\md5.cpp")
    assert len(parser.lines[path]) == 19


SAMPLE_REGEX_BREAK = """\
** Module: "test.obj"

  C:\\test\\list (None), (None), 0001:000001C0-000001C1, line/addr pairs = 1

      1 000001C0  
"""


def test_regex_attack():
    """Can we withstand a filename designed to defeat our regular expression?"""
    parser = CvdumpParser()
    parser.read_section("LINES", SAMPLE_REGEX_BREAK)

    path = PureWindowsPath("C:\\test\\list (None),")
    assert path in parser.lines
