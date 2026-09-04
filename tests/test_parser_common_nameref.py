"""Testing behavior common to all name annotations completed by a comment."""

from textwrap import dedent
import pytest
from reccmp.parser.parser import DecompParser
from reccmp.parser.marker import MarkerType
from .parser_helpers import (
    AnnotationType,
    NAME_ANNOTATIONS,
    completion_token,
    xfail_param,
)


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    return DecompParser()


NAMEREF_TYPES = [marker_type for marker_type, _ in NAME_ANNOTATIONS]

# fmt: off
WHITESPACE_VARIANTS = [
    pytest.param("",     "",     id="base case"),
    pytest.param("   ",  "",     id="extra leading spaces"),
    pytest.param(" ",    "   ",  id="trailing spaces"),
    pytest.param("   ",  "   ",  id="leading and trailing spaces"),
    pytest.param("\t",   "\t",   id="leading and trailing tab"),
    pytest.param(" \t",  " \t",  id="mixed whitespace chars"),
]
# fmt: on


@pytest.mark.parametrize("prefix, suffix", WHITESPACE_VARIANTS)
@pytest.mark.parametrize("marker_type", NAMEREF_TYPES)
def test_strip_whitespace(
    parser: DecompParser, marker_type: MarkerType, prefix: str, suffix: str
):
    """Should strip leading and trailing whitespace from the name.
    GH #55, #184, #512"""
    token = completion_token(
        marker_type, AnnotationType.NAME, name_prefix=prefix, name_suffix=suffix
    )
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        {token}
        """))

    # Captured the symbol.
    (symbol,) = parser.iter_symbols()
    assert (symbol.type, symbol.module, symbol.offset) == (marker_type, "TEST", 0x1234)

    # We are not checking the specific nameref parsing rules here.
    # Just make sure leading and trailing whitespace was removed.
    assert symbol.name == symbol.name.strip()

    # Undecided on whether we should warn, but we don't for now.
    assert not parser.alerts


# TODO: Replace with NAMEREF_TYPES when xfails are resolved.
SCOPE_TYPES = [
    MarkerType.FUNCTION,
    xfail_param(MarkerType.GLOBAL, reason="No separate code path for nameref case."),
    MarkerType.STRING,
    xfail_param(MarkerType.VTABLE, reason="No separate code path for nameref case."),
    MarkerType.SYNTHETIC,
    MarkerType.TEMPLATE,
    MarkerType.LIBRARY,
]


@pytest.mark.parametrize("scope_token", ["class", "struct", "namespace"])
@pytest.mark.parametrize("marker_type", SCOPE_TYPES)
def test_enclosing_scope(
    parser: DecompParser, marker_type: MarkerType, scope_token: str
):
    """Should not add a scope to a name annotation. GH #537"""
    scope_name = "Pizza"
    token = completion_token(marker_type, AnnotationType.NAME)

    # Make sure our scope is not part of the completion token already,
    # because we are not checking the name.
    assert scope_name not in token

    parser.read(dedent(f"""\
        {scope_token} {scope_name} {{
        // {marker_type.name}: TEST 0x1234
        {token}
        }}
        """))

    # Captured the symbol.
    (symbol,) = parser.iter_symbols()
    assert scope_name not in symbol.name

    # No warnings.
    assert not parser.alerts
