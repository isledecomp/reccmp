"""Tests for the STRING marker."""

from textwrap import dedent
import pytest
from reccmp.parser.error import AlertCode
from reccmp.parser.parser import DecompParser
from reccmp.parser.marker import MarkerType
from .parser_helpers import (
    sorted_alerts,
    symbol_tuples,
)


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    return DecompParser()


def test_code_string(parser: DecompParser):
    """Should read the string from a code token."""
    parser.read(dedent("""\
        // STRING: TEST 0x1234
        char* g_message = "hello";
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.STRING, "TEST", 0x1234)]
    assert parser.strings[0].name == "hello"

    # No warnings.
    assert not parser.alerts


def test_comment_string(parser: DecompParser):
    """Should read the string from a comment."""
    parser.read(dedent("""\
        // STRING: TEST 0x1234
        // "hello"
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.STRING, "TEST", 0x1234)]
    assert parser.strings[0].name == "hello"

    # No warnings.
    assert not parser.alerts


def test_define_string(parser: DecompParser):
    """Should read the string from a #define token."""
    parser.read(dedent("""\
        // STRING: TEST 0x1234
        #define MESSAGE "hello"
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.STRING, "TEST", 0x1234)]
    assert parser.strings[0].name == "hello"

    # No warnings.
    assert not parser.alerts


def test_code_widechar_string(parser: DecompParser):
    """Should detect a widechar string in a code token."""
    parser.read(dedent("""\
        // STRING: TEST 0x1234
        wchar_t* g_message = L"hello";
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.STRING, "TEST", 0x1234)]
    assert parser.strings[0].name == "hello"
    assert parser.strings[0].is_widechar is True

    # No warnings.
    assert not parser.alerts


def test_comment_widechar_string(parser: DecompParser):
    """Should detect a widechar string in a comment."""
    parser.read(dedent("""\
        // STRING: TEST 0x1234
        // L"hello"
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.STRING, "TEST", 0x1234)]
    assert parser.strings[0].name == "hello"
    assert parser.strings[0].is_widechar is True

    # No warnings.
    assert not parser.alerts


def test_define_widechar_string(parser: DecompParser):
    """Should detect a widechar string in a #define token."""
    parser.read(dedent("""\
        // STRING: TEST 0x1234
        #define MESSAGE L"hello"
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.STRING, "TEST", 0x1234)]
    assert parser.strings[0].name == "hello"
    assert parser.strings[0].is_widechar is True

    # No warnings.
    assert not parser.alerts


# fmt: off
COMPLETION_NOT_FOUND = (
    pytest.param("",                  AlertCode.STRING_NOT_FOUND, id="end of file"),
    pytest.param(";",                 AlertCode.STRING_NOT_FOUND, id="semicolon"),
    pytest.param("//",                AlertCode.NO_SUITABLE_NAME, id="empty comment"),
    pytest.param("// hello",          AlertCode.STRING_NOT_FOUND, id="comment not quoted"),
    pytest.param("#define MESSAGE 5", AlertCode.STRING_NOT_FOUND, id="define without string"),
)
# fmt: on


@pytest.mark.parametrize("code, alert_code", COMPLETION_NOT_FOUND)
def test_completion_not_found(parser: DecompParser, code: str, alert_code: AlertCode):
    """Should reject the marker if we do not find a completion token."""
    parser.read(dedent(f"""\
        // STRING: TEST 0x1234
        {code}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error on the line of the marker.
    assert sorted_alerts(parser) == [(alert_code, 1)]
