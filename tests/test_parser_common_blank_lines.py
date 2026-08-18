"""Each blank line in a marker group results in an AlertCode.UNEXPECTED_BLANK_LINE warning."""

from textwrap import dedent
import pytest
from reccmp.parser.parser import DecompParser
from reccmp.parser.error import AlertCode
from reccmp.parser.marker import MarkerType
from .parser_helpers import (
    AnnotationType,
    VALID_ANNOTATIONS,
    completion_token,
    sorted_alerts,
    symbol_tuples,
    xfail_param,
)


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    return DecompParser()


# fmt: off
TEST_CASES = [
    (MarkerType.FUNCTION, AnnotationType.LINE),
    (MarkerType.STUB,     AnnotationType.LINE),
    (MarkerType.GLOBAL,   AnnotationType.LINE),
    (MarkerType.STRING,   AnnotationType.LINE),
    xfail_param(MarkerType.VTABLE,   AnnotationType.LINE),
    #
    (MarkerType.FUNCTION,  AnnotationType.NAME),
    (MarkerType.GLOBAL,    AnnotationType.NAME),
    (MarkerType.STRING,    AnnotationType.NAME),
    xfail_param(MarkerType.VTABLE,    AnnotationType.NAME),
    xfail_param(MarkerType.SYNTHETIC, AnnotationType.NAME),
    xfail_param(MarkerType.TEMPLATE,  AnnotationType.NAME),
    xfail_param(MarkerType.LIBRARY,   AnnotationType.NAME),
]
# fmt: on


# Sanity check: remove after xfails are resolved
# and replace the parameter list with VALID_ANNOTATIONS.
if len(TEST_CASES) != len(VALID_ANNOTATIONS):
    pytest.fail(
        "Local TEST_CASES does not shadow VALID_ANNOTATIONS",
    )


@pytest.mark.parametrize("marker_type, annotation_type", TEST_CASES)
def test_blanks_between_markers(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warns for a blank line between markers in a group."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234

        // {marker_type.name}: HELLO 0x5555
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]

    # One warning for the blank line.
    assert sorted_alerts(parser) == [(AlertCode.UNEXPECTED_BLANK_LINE, 2)]


@pytest.mark.parametrize("marker_type, annotation_type", TEST_CASES)
def test_blanks_after_markers(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warns for a blank line between the last marker in a group and the completion token."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234

        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # One warning for the blank line.
    assert sorted_alerts(parser) == [(AlertCode.UNEXPECTED_BLANK_LINE, 2)]


@pytest.mark.parametrize("marker_type, annotation_type", TEST_CASES)
def test_multiple_blanks(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warns for every blank line in a marker sequence, even if they are contiguous."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234


        // {marker_type.name}: HELLO 0x5555


        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]

    # One warning for each blank line.
    assert sorted_alerts(parser) == [
        (AlertCode.UNEXPECTED_BLANK_LINE, 2),
        (AlertCode.UNEXPECTED_BLANK_LINE, 3),
        (AlertCode.UNEXPECTED_BLANK_LINE, 5),
        (AlertCode.UNEXPECTED_BLANK_LINE, 6),
    ]
