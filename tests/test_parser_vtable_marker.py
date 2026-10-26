"""Tests for the VTABLE marker."""

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


CLASS_KEYWORDS = ("class", "struct")


@pytest.mark.parametrize("keyword", CLASS_KEYWORDS)
def test_code_class(parser: DecompParser, keyword: str):
    """Should read the name from a class or struct declaration."""
    parser.read(dedent(f"""\
        // VTABLE: TEST 0x1234
        {keyword} Test {{
        }};
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.VTABLE, "TEST", 0x1234)]
    assert parser.vtables[0].name == "Test"

    # No warnings.
    assert not parser.alerts


def test_code_class_superclass(parser: DecompParser):
    """Should read the name from a class declaration with a superclass list."""
    parser.read(dedent("""\
        // VTABLE: TEST 0x1234
        class Test : public Base, public Other {
        };
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.VTABLE, "TEST", 0x1234)]
    assert parser.vtables[0].name == "Test"

    # No warnings.
    assert not parser.alerts


def test_code_class_size_comment(parser: DecompParser):
    """Should skip a SIZE comment between the marker and the class declaration."""
    parser.read(dedent("""\
        // VTABLE: TEST 0x1234
        // SIZE 0x10
        class Test {
        };
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.VTABLE, "TEST", 0x1234)]
    assert parser.vtables[0].name == "Test"

    # No warnings.
    assert not parser.alerts


@pytest.mark.parametrize("keyword", CLASS_KEYWORDS)
def test_comment_class(parser: DecompParser, keyword: str):
    """Should read the name from a comment that starts with class or struct.
    (This is required so that we skip the SIZE comment seen above.)"""
    parser.read(dedent(f"""\
        // VTABLE: TEST 0x1234
        // {keyword} Test
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.VTABLE, "TEST", 0x1234)]
    assert parser.vtables[0].name == "Test"

    # No warnings.
    assert not parser.alerts


@pytest.mark.xfail(reason="TODO: #509")
def test_comment_without_keyword(parser: DecompParser):
    """Should read the name from a comment without a class or struct prefix."""
    parser.read(dedent("""\
        // VTABLE: TEST 0x1234
        // Test
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.VTABLE, "TEST", 0x1234)]
    assert parser.vtables[0].name == "Test"

    # No warnings.
    assert not parser.alerts


def test_folded_option_by_target(parser: DecompParser):
    """The FOLDED option applies only to the marker where it appears.
    It does not set a base class."""
    parser.read(dedent("""\
        // VTABLE: HELLO 0x1234 FOLDED
        // VTABLE: TEST 0x5555
        class Test {
        };
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (MarkerType.VTABLE, "HELLO", 0x1234),
        (MarkerType.VTABLE, "TEST", 0x5555),
    ]
    assert parser.vtables[0].is_folded is True
    assert parser.vtables[0].base_class is None
    assert parser.vtables[1].is_folded is False

    # No warnings.
    assert not parser.alerts


def test_base_class(parser: DecompParser):
    """Should read the base class from the marker's extra text.
    A marker without extra text has no base class."""
    parser.read(dedent("""\
        // VTABLE: TEST 0x1000
        // VTABLE: TEST 0x2000 Base
        // VTABLE: TEST 0x3000 Other
        class RaceActor : public Actor {
        };
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (MarkerType.VTABLE, "TEST", 0x1000),
        (MarkerType.VTABLE, "TEST", 0x2000),
        (MarkerType.VTABLE, "TEST", 0x3000),
    ]
    assert all(vtable.name == "RaceActor" for vtable in parser.vtables)
    assert parser.vtables[0].base_class is None
    assert parser.vtables[1].base_class == "Base"
    assert parser.vtables[2].base_class == "Other"
    assert not any(vtable.is_folded for vtable in parser.vtables)

    # No warnings.
    assert not parser.alerts


def test_namespace(parser: DecompParser):
    """Should reject a VTABLE marker above a namespace. (GH #509)"""
    parser.read(dedent("""\
        // VTABLE: TEST 0x1234
        namespace Test {
        }
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error on the line of the marker.
    assert sorted_alerts(parser) == [(AlertCode.NO_SUITABLE_NAME, 1)]


@pytest.mark.parametrize("keyword", CLASS_KEYWORDS)
def test_forward_declaration(parser: DecompParser, keyword: str):
    """Rejects a VTABLE marker above a forward declaration."""
    parser.read(dedent(f"""\
        // VTABLE: TEST 0x1234
        {keyword} Test;
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error on the line of the marker.
    assert sorted_alerts(parser) == [(AlertCode.NO_SUITABLE_NAME, 1)]


# fmt: off
COMPLETION_NOT_FOUND = (
    pytest.param("",                  AlertCode.NO_SUITABLE_NAME, id="end of file"),
    pytest.param(";",                 AlertCode.NO_SUITABLE_NAME, id="semicolon"),
    pytest.param("//",                AlertCode.NO_SUITABLE_NAME, id="empty comment"),
)
# fmt: on


@pytest.mark.parametrize("code, alert_code", COMPLETION_NOT_FOUND)
def test_completion_not_found(parser: DecompParser, code: str, alert_code: AlertCode):
    """Should reject the marker if we do not find a completion token."""
    parser.read(dedent(f"""\
        // VTABLE: TEST 0x1234
        {code}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error on the line of the marker.
    assert sorted_alerts(parser) == [(alert_code, 1)]
