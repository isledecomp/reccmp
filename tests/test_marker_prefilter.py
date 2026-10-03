"""COULD_BE_MARKER decides whether a file is parsed at all, so it has to match
everything markerRegex can. If it ever stops doing that, reccmp silently loses
annotations, which these tests exist to prevent."""

from pathlib import PurePath
import pytest
from reccmp.parser.marker import COULD_BE_MARKER, markerRegex
from reccmp.parser.parser import DecompParser

# Lines markerRegex accepts, including the spellings its \\s* and re.I allow.
MARKER_LINES = [
    "// FUNCTION: TEST 0x1234",
    "  // FUNCTION: TEST 0x1234",
    "\t// FUNCTION: TEST 0x1234",
    "//FUNCTION: TEST 0x1234",
    "//   FUNCTION:   TEST   0x1234",
    "// function: test 0x1234",
    "// FuNcTiOn: TeSt 0XABCDEF",
    "// STUB: TEST 0x1234",
    "// SYNTHETIC: TEST 0x1234",
    "// VTABLE: TEST 0x1234",
    "// GLOBAL: TEST 0x1234",
    "// STRING: TEST 0x1234 'hello'",
    "// LIBRARY: TEST 0x1234",
    "// LINE: TEST 0x1234",
    "// TEMPLATE: TEST 0x1234",
    "// NOT_A_REAL_TYPE: TEST 0x1234",
    "// FUNCTION: TEST123 0x1234",
    "// FUNCTION: TEST 0xa",
    "// FUNCTION: TEST 0x1234 extra text here",
]


@pytest.mark.parametrize("line", MARKER_LINES)
def test_prefilter_accepts_every_marker(line: str):
    """The superset property, checked against markerRegex itself."""
    assert markerRegex.match(line) is not None, "sample is not a marker"
    assert COULD_BE_MARKER.search(line) is not None


def test_prefilter_accepts_a_marker_anywhere_in_a_file():
    text = "int main() {\n  return 0;\n}\n// FUNCTION: TEST 0x1234\nvoid f() {}\n"
    assert COULD_BE_MARKER.search(text) is not None


@pytest.mark.parametrize(
    "text",
    [
        "",
        "int main() { return 0; }\n",
        "// an ordinary comment\n",
        "// a comment mentioning 0x1234\n",
        "/* FUNCTION: TEST 0x1234 */\n",
        "int x = 0x1234;\n",
        "// TODO: fix this\n",
    ],
)
def test_prefilter_rejects_files_without_a_marker(text: str):
    """Not required for correctness, but the saving comes from these."""
    assert COULD_BE_MARKER.search(text) is None


def parse(text: str) -> DecompParser:
    parser = DecompParser()
    parser.reset_and_set_filename(PurePath("test.cpp"))
    parser.read(text)
    return parser


def test_file_with_a_marker_is_still_parsed():
    parser = parse("// FUNCTION: TEST 0x1234\nvoid f() {\n}\n")
    assert len(list(parser.iter_symbols("TEST"))) == 1


def test_file_without_a_marker_yields_nothing():
    parser = parse("namespace a {\nvoid f() {\n}\n}\n")
    assert not list(parser.iter_symbols("TEST"))
    assert not parser.alerts


def test_skipped_file_does_not_keep_the_previous_scopes():
    """read() returns early for a file with no marker; it must not leave the
    last file's namespaces behind for a caller that does not reset."""
    parser = parse("namespace outer {\n// FUNCTION: TEST 0x1234\nvoid f() {\n}\n}\n")
    assert parser.namespaces

    parser.read("void unannotated() {\n}\n")
    assert not parser.namespaces
