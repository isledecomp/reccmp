"""Each blank line in a marker group results in an AlertCode.UNEXPECTED_BLANK_LINE warning."""

from textwrap import dedent
import pytest
from reccmp.parser.parser import DecompParser
from reccmp.parser.error import AlertCode
from reccmp.parser.marker import MarkerType
from .parser_helpers import (
    AnnotationType,
    PARTIAL_ANNOTATIONS,
    completion_token,
    sorted_alerts,
    symbol_tuples,
)


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    return DecompParser()


@pytest.mark.parametrize("marker_type, annotation_type", PARTIAL_ANNOTATIONS)
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


@pytest.mark.parametrize("marker_type, annotation_type", PARTIAL_ANNOTATIONS)
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


@pytest.mark.parametrize("marker_type, annotation_type", PARTIAL_ANNOTATIONS)
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


def test_one_alert_for_compatible_marker_types(parser: DecompParser):
    """Warns once for each blank line in a marker sequence of different types."""
    parser.read(dedent("""\
        // STRING: TEST 0x5555

        // GLOBAL: TEST 0x1234

        const char* xyz = "test";
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (MarkerType.STRING, "TEST", 0x5555),
        (MarkerType.GLOBAL, "TEST", 0x1234),
    ]

    # One warning for each blank line.
    assert sorted_alerts(parser) == [
        (AlertCode.UNEXPECTED_BLANK_LINE, 2),
        (AlertCode.UNEXPECTED_BLANK_LINE, 4),
    ]


@pytest.mark.parametrize("marker_type, annotation_type", PARTIAL_ANNOTATIONS)
def test_blanks_after_unknown_marker(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warns for a blank lines after an unknown marker type.
    The unknown marker is still part of the sequence."""
    parser.read(dedent(f"""\
        // BANANA: TEST 0x5555

        // {marker_type.name}: TEST 0x1234
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all valid markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # One warning for the blank line.
    assert sorted_alerts(parser) == [
        (AlertCode.UNKNOWN_ANNOTATION, 1),
        (AlertCode.UNEXPECTED_BLANK_LINE, 2),
    ]


def test_blanks_without_completion(parser: DecompParser):
    """Warns for a blank lines following an incomplete marker."""
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1234

        void test();
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # One warning for the blank line.
    assert sorted_alerts(parser) == [
        (AlertCode.NO_IMPLEMENTATION, 1),
        (AlertCode.UNEXPECTED_BLANK_LINE, 2),
    ]


@pytest.mark.parametrize("marker_type, _", PARTIAL_ANNOTATIONS)
def test_blanks_before_end_of_file(
    parser: DecompParser, marker_type: MarkerType, _: AnnotationType
):
    """Warns for a blank line between markers if the file ends before any completion token."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234

        // {marker_type.name}: HELLO 0x5555
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # The alert code varies for the incomplete markers.
    alerts = sorted_alerts(parser)
    assert len(alerts) == 3
    assert (AlertCode.UNEXPECTED_BLANK_LINE, 2) in alerts


def test_blanks_between_line_markers(parser: DecompParser):
    """Do not warn for blank lines between LINE markers."""
    parser.read(dedent("""\
        // LINE: TEST 0x1234

        // LINE: HELLO 0x5555

        test();
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (MarkerType.LINE, "TEST", 0x1234),
        (MarkerType.LINE, "HELLO", 0x5555),
    ]

    # No warnings.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type, annotation_type", PARTIAL_ANNOTATIONS)
def test_blanks_between_line_then_other_type(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Do not warn for blank lines between a LINE marker and a marker of any other type."""
    parser.read(dedent(f"""\
        // LINE: HELLO 0x5555

        // {marker_type.name}: TEST 0x1234
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (MarkerType.LINE, "HELLO", 0x5555),
        (marker_type, "TEST", 0x1234),
    ]

    # No warnings.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type, annotation_type", PARTIAL_ANNOTATIONS)
def test_blanks_after_marker_with_line_first(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warn for blank lines between a marker and the completion token if a LINE is first in the sequence."""
    parser.read(dedent(f"""\
        // LINE: HELLO 0x5555

        // {marker_type.name}: TEST 0x1234

        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (MarkerType.LINE, "HELLO", 0x5555),
        (marker_type, "TEST", 0x1234),
    ]

    # One warning for the blank line between the second marker and the completion token.
    assert sorted_alerts(parser) == [
        (AlertCode.UNEXPECTED_BLANK_LINE, 4),
    ]


@pytest.mark.parametrize("marker_type, annotation_type", PARTIAL_ANNOTATIONS)
def test_blanks_after_marker_with_line_second(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warn for all blank lines in a marker sequence that contains LINE where it is not first."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234

        // LINE: HELLO 0x5555

        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (MarkerType.LINE, "HELLO", 0x5555),
    ]

    # One warning for each blank line.
    assert sorted_alerts(parser) == [
        (AlertCode.UNEXPECTED_BLANK_LINE, 2),
        (AlertCode.UNEXPECTED_BLANK_LINE, 4),
    ]
