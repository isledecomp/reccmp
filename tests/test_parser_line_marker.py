"""Tests for the LINE marker.

LINE markers are valid anywhere in the file and can appear in sequence with any marker type.
"""

from textwrap import dedent
import pytest
from reccmp.parser.error import AlertCode
from reccmp.parser.parser import DecompParser
from reccmp.parser.marker import MarkerType
from .parser_helpers import (
    AnnotationType,
    VALID_ANNOTATIONS,
    completion_token,
    sorted_alerts,
    symbol_tuples,
)


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    return DecompParser()


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_line_marker_first(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Should accept LINE markers in a sequence with other markers where LINE is first."""
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


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_line_marker_second(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Should accept LINE markers in a sequence with other markers where LINE is second."""
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

    # No warnings.
    assert not parser.alerts


def test_line_markers_same_module(parser: DecompParser):
    """Should accept LINE markers in sequence from the same module."""
    parser.read(dedent("""\
        // LINE: TEST 0x1234
        // LINE: TEST 0x5555
        test();
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (MarkerType.LINE, "TEST", 0x1234),
        (MarkerType.LINE, "TEST", 0x5555),
    ]

    # No warnings.
    assert not parser.alerts


def test_line_markers_before_eof(parser: DecompParser):
    """Should accept LINE markers part of a marker sequence where
    a completion token is expected but does not appear."""
    parser.read(dedent("""\
        // LINE: HELLO 0x5555
        // LINE: HELLO 0x6666
        // FUNCTION: TEST 0x1234"""))

    # Captured all LINE markers.
    assert symbol_tuples(parser) == [
        (MarkerType.LINE, "HELLO", 0x5555),
        (MarkerType.LINE, "HELLO", 0x6666),
    ]

    # Warn for the incomplete FUNCTION marker only.
    assert sorted_alerts(parser) == [
        (AlertCode.MISSED_START_OF_FUNCTION, 3),
    ]
