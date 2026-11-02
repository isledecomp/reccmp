"""Tests for function marker types."""

from itertools import permutations
from textwrap import dedent
import pytest
from reccmp.parser.error import AlertCode
from reccmp.parser.parser import DecompParser
from reccmp.parser.marker import MarkerType
from .parser_helpers import (
    AnnotationType,
    FUNCTION_ANNOTATIONS,
    LINE_FUNCTION_TYPES,
    NAME_ONLY_FUNCTION_TYPES,
    NAMEREF_FUNCTION_TYPES,
    completion_token,
    sorted_alerts,
    symbol_tuples,
)


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    return DecompParser()


@pytest.mark.parametrize("marker_type", LINE_FUNCTION_TYPES)
def test_line_function(parser: DecompParser, marker_type: MarkerType):
    """Should accept a function marker above a function implementation."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        {completion_token(marker_type, AnnotationType.LINE)}
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(marker_type, "TEST", 0x1234)]
    assert parser.functions[0].lookup_by_name is False

    # No warnings.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type", NAMEREF_FUNCTION_TYPES)
def test_nameref_function(parser: DecompParser, marker_type: MarkerType):
    """Should read the function name from a comment."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        {completion_token(marker_type, AnnotationType.NAME)}
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [(marker_type, "TEST", 0x1234)]
    assert parser.functions[0].name == "Test::Function"
    assert parser.functions[0].lookup_by_name is True

    # No warnings.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type", LINE_FUNCTION_TYPES)
def test_missed_start_of_function(parser: DecompParser, marker_type: MarkerType):
    """Should reject a function marker if the closing curly bracket is hit before the opening bracket."""
    parser.read(dedent(f"""\
        void test()
        {{
        // {marker_type.name}: TEST 0x1234
        }}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error on the line of each marker.
    assert sorted_alerts(parser) == [(AlertCode.MISSED_START_OF_FUNCTION, 3)]


@pytest.mark.parametrize("marker_type", LINE_FUNCTION_TYPES)
def test_missed_start_of_function_imbalance(
    parser: DecompParser, marker_type: MarkerType
):
    """Should reject a function marker if the closing curly bracket is hit before the opening bracket.
    In this case, we also report on global bracket imbalance."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        void test()
        }}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error on the line of each marker, plus global imbalance error.
    assert sorted_alerts(parser) == [
        (AlertCode.MISSED_START_OF_FUNCTION, 1),
        (AlertCode.CURLY_BRACKET_IMBALANCE, 1),
    ]


@pytest.mark.parametrize("marker_type", LINE_FUNCTION_TYPES)
def test_missed_start_of_function_curly_first(
    parser: DecompParser, marker_type: MarkerType
):
    """Should reject a function marker if the opening curly bracket is hit before the function signature."""
    parser.read(dedent(f"""\
        void test()
        // {marker_type.name}: TEST 0x1234
        {{
        }}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error on the line of each marker.
    assert sorted_alerts(parser) == [(AlertCode.MISSED_START_OF_FUNCTION, 2)]


@pytest.mark.parametrize("marker_type", LINE_FUNCTION_TYPES)
def test_function_comment_before_curly(parser: DecompParser, marker_type: MarkerType):
    """Should allow a line comment to appear between the function signature and the curly bracket."""
    parser.read(f"""\
        // {marker_type.name}: TEST 0x1234
        void Test::Method()
        // vtable+0x08
        {{
        }}
        """)

    # Captured the marker.
    assert symbol_tuples(parser) == [(marker_type, "TEST", 0x1234)]
    assert parser.functions[0].lookup_by_name is False
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 5

    # No warnings.
    assert not sorted_alerts(parser)


@pytest.mark.xfail(reason="TODO: #509")
@pytest.mark.parametrize("keyword", ["if", "else if", "switch", "for", "while"])
@pytest.mark.parametrize("marker_type", LINE_FUNCTION_TYPES)
def test_not_a_function(
    parser: DecompParser,
    marker_type: MarkerType,
    keyword: str,
):
    """Should distinguish curly bracket sequences that are not functions."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        {keyword} (x) {{
        }}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Raised some error. (TODO: New AlertCode)
    assert sorted_alerts(parser)


@pytest.mark.parametrize("marker_type", NAME_ONLY_FUNCTION_TYPES)
def test_bad_nameref(parser: DecompParser, marker_type: MarkerType):
    """Should reject the name-only marker types if the completion token is a code function."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        {completion_token(MarkerType.FUNCTION, AnnotationType.LINE)}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error on the line of each marker.
    assert sorted_alerts(parser) == [(AlertCode.BAD_NAMEREF, 1)]


@pytest.mark.parametrize("marker_type", NAME_ONLY_FUNCTION_TYPES)
def test_bad_nameref_mixed(parser: DecompParser, marker_type: MarkerType):
    """Should flag only the name-only markers with BAD_NAMEREF.
    Should accept FUNCTION markers in the sequence, provided they are for a different target.
    """
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        // FUNCTION: HELLO 0x5555
        {completion_token(MarkerType.FUNCTION, AnnotationType.LINE)}
        """))

    # Captured the FUNCTION marker.
    assert symbol_tuples(parser) == [(MarkerType.FUNCTION, "HELLO", 0x5555)]

    # Error on the line for the name-only marker type.
    assert sorted_alerts(parser) == [(AlertCode.BAD_NAMEREF, 1)]


# STUB markers are not checked for VARYING_MARKER_TYPES.
VARYING_FUNCTION_TYPES = tuple(
    marker_type
    for marker_type in NAMEREF_FUNCTION_TYPES
    if marker_type != MarkerType.STUB
)


@pytest.mark.parametrize(
    "first_type, second_type", tuple(permutations(VARYING_FUNCTION_TYPES, 2))
)
def test_varying_marker_types(
    parser: DecompParser, first_type: MarkerType, second_type: MarkerType
):
    """Should accept a nameref annotation that uses different function marker types,
    but warn on the marker whose type differs from the first."""
    parser.read(dedent(f"""\
        // {first_type.name}: TEST 0x1234
        // {second_type.name}: HELLO 0x5555
        {completion_token(first_type, AnnotationType.NAME)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (first_type, "TEST", 0x1234),
        (second_type, "HELLO", 0x5555),
    ]

    # Warning for each marker in the sequence
    assert sorted_alerts(parser) == [
        (AlertCode.VARYING_MARKER_TYPES, 1),
        (AlertCode.VARYING_MARKER_TYPES, 2),
    ]


@pytest.mark.parametrize("marker_type", VARYING_FUNCTION_TYPES)
def test_varying_marker_types_stub_first(parser: DecompParser, marker_type: MarkerType):
    """Should not report varying marker types between two markers if STUB is first."""
    parser.read(dedent(f"""\
        // STUB: TEST 0x1234
        // {marker_type.name}: HELLO 0x5555
        {completion_token(marker_type, AnnotationType.NAME)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (MarkerType.STUB, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]

    # No warnings.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type", VARYING_FUNCTION_TYPES)
def test_varying_marker_types_stub_second(
    parser: DecompParser, marker_type: MarkerType
):
    """Should not report varying marker types between two markers if STUB is second."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        // STUB: HELLO 0x5555
        {completion_token(marker_type, AnnotationType.NAME)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (MarkerType.STUB, "HELLO", 0x5555),
    ]

    # No warnings.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type", LINE_FUNCTION_TYPES)
def test_symbol_option_ignored(parser: DecompParser, marker_type: MarkerType):
    """Should ignore the SYMBOL option for a line marker."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234 SYMBOL
        {completion_token(marker_type, AnnotationType.LINE)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [(marker_type, "TEST", 0x1234)]

    # The option has no effect.
    assert parser.functions[0].name_is_symbol is False

    # Warning on the line of the marker.
    assert sorted_alerts(parser) == [(AlertCode.SYMBOL_OPTION_IGNORED, 1)]


@pytest.mark.parametrize("marker_type", NAMEREF_FUNCTION_TYPES)
def test_symbol_option_by_target(parser: DecompParser, marker_type: MarkerType):
    """Should apply the SYMBOL option for a nameref marker."""
    parser.read(dedent(f"""\
        // {marker_type.name}: HELLO 0x1234 SYMBOL
        // {marker_type.name}: TEST 0x5555
        // _strcmp
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "HELLO", 0x1234),
        (marker_type, "TEST", 0x5555),
    ]

    # Options apply only to the markers where they appear.
    assert parser.functions[0].name_is_symbol is True
    assert parser.functions[1].name_is_symbol is False

    # No warnings.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type, annotation_type", FUNCTION_ANNOTATIONS)
def test_folded_option_by_target(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Should apply the FOLDED option to a function marker."""
    parser.read(dedent(f"""\
        // {marker_type.name}: HELLO 0x1234 FOLDED
        // {marker_type.name}: TEST 0x5555
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "HELLO", 0x1234),
        (marker_type, "TEST", 0x5555),
    ]

    # Options apply only to the markers where they appear.
    assert parser.functions[0].is_folded is True
    assert parser.functions[1].is_folded is False

    # No warnings.
    assert not parser.alerts


# fmt: off
COMPLETION_NOT_FOUND = (
    pytest.param("",             AlertCode.MISSED_START_OF_FUNCTION, id="end of file"),
    pytest.param(";",            AlertCode.MISSED_START_OF_FUNCTION, id="semicolon"),
    pytest.param("void test()",  AlertCode.MISSED_START_OF_FUNCTION, id="signature then end of file"),
    pytest.param("void test();", AlertCode.NO_IMPLEMENTATION,        id="declaration"),
    pytest.param("//",           AlertCode.NO_SUITABLE_NAME,         id="empty comment"),
)
# fmt: on


@pytest.mark.parametrize("code, alert_code", COMPLETION_NOT_FOUND)
@pytest.mark.parametrize("marker_type", LINE_FUNCTION_TYPES)
def test_completion_not_found(
    parser: DecompParser, marker_type: MarkerType, code: str, alert_code: AlertCode
):
    """Should reject the marker if we do not find a completion token."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        {code}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error on the line of the marker.
    assert sorted_alerts(parser) == [(alert_code, 1)]
