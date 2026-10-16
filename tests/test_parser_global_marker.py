"""Tests for the GLOBAL marker."""

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


def test_code_variable(parser: DecompParser):
    """Should read the name from a variable declaration."""
    parser.read(dedent("""\
        // GLOBAL: TEST 0x1234
        int count = 0;
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.GLOBAL, "TEST", 0x1234)]
    assert parser.variables[0].name == "count"
    assert parser.variables[0].is_static is False

    # No warnings.
    assert not parser.alerts


def test_comment_variable(parser: DecompParser):
    """Should read the name from a comment."""
    parser.read(dedent("""\
        // GLOBAL: TEST 0x1234
        // count
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.GLOBAL, "TEST", 0x1234)]
    assert parser.variables[0].name == "count"
    assert parser.variables[0].is_static is False

    # No warnings.
    assert not parser.alerts


def test_static_keyword_outside_function(parser: DecompParser):
    """Should not set the static flag unless the variable is inside a function."""
    parser.read(dedent("""\
        // GLOBAL: TEST 0x1234
        static int count = 0;
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(MarkerType.GLOBAL, "TEST", 0x1234)]
    assert parser.variables[0].name == "count"
    assert parser.variables[0].is_static is False

    # No warnings.
    assert not parser.alerts


def test_static_variable(parser: DecompParser):
    """Should mark a static variable if its function is also annotated for the same target."""
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1234
        void test()
        {
            // GLOBAL: TEST 0x5555
            static int count = 0;
        }
        """))

    # Captured the function and variable.
    assert symbol_tuples(parser) == [
        (MarkerType.FUNCTION, "TEST", 0x1234),
        (MarkerType.GLOBAL, "TEST", 0x5555),
    ]
    assert parser.variables[0].name == "count"
    assert parser.variables[0].is_static is True
    assert parser.variables[0].parent_function == 0x1234

    # No warnings.
    assert not parser.alerts


def test_static_variable_function_not_marked_for_target(parser: DecompParser):
    """If a variable is known to be static (the parent function and variable are paired for at least one target)
    reject any markers for a target where the function is NOT annotated."""
    parser.read(dedent("""\
        // FUNCTION: HELLO 0x1234
        void test()
        {
            // GLOBAL: HELLO 0x5555
            // GLOBAL: TEST 0x5555
            static int count = 0;
        }
        """))

    # Captured the function and variable from the same target.
    assert symbol_tuples(parser) == [
        (MarkerType.FUNCTION, "HELLO", 0x1234),
        (MarkerType.GLOBAL, "HELLO", 0x5555),
    ]

    # Error for the marker from the target without a corresponding FUNCTION annotation.
    assert sorted_alerts(parser) == [(AlertCode.ORPHANED_STATIC_VARIABLE, 5)]


# fmt: off
COMPLETION_NOT_FOUND = (
    pytest.param("",                  AlertCode.NO_SUITABLE_NAME, id="end of file"),
    pytest.param(";",                 AlertCode.NO_SUITABLE_NAME, id="semicolon"),
    pytest.param("//",                AlertCode.NO_SUITABLE_NAME, id="empty comment"),
    pytest.param('"hello";',          AlertCode.NO_SUITABLE_NAME, id="string literal"),
    pytest.param("#define MESSAGE 5", AlertCode.NO_SUITABLE_NAME, id="define"),
)
# fmt: on


@pytest.mark.parametrize("code, alert_code", COMPLETION_NOT_FOUND)
def test_completion_not_found(parser: DecompParser, code: str, alert_code: AlertCode):
    """Rejects the marker if no variable name follows it."""
    parser.read(dedent(f"""\
        // GLOBAL: TEST 0x1234
        {code}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error on the line of the marker.
    assert sorted_alerts(parser) == [(alert_code, 1)]
