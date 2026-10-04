"""All lines in a marker sequence must have the same indent level using the
same whitespace characters.

If there is any disagreement, record AlertCode.MARKER_NOT_ALIGNED for each line.
"""

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
)


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    return DecompParser()


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_aligned(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Does not warn for single marker aligned to completion token."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # No warning.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_aligned_indented(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Does not warn for single marker aligned to completion token
    when both are indented."""
    parser.read(dedent(f"""\
        class Test {{
            // {marker_type.name}: TEST 0x1234
            {completion_token(marker_type, annotation_type)}
        }};
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # No warning.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_group_aligned(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Does not warn for marker group aligned to completion token."""
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

    # No warning.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_group_aligned_indented(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Does not warn for marker group aligned to completion token
    when all lines are indented."""
    parser.read(dedent(f"""\
        class Test {{
            // {marker_type.name}: TEST 0x1234
            // {marker_type.name}: HELLO 0x5555
            {completion_token(marker_type, annotation_type)}
        }};
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]

    # No warning.
    assert not parser.alerts


@pytest.mark.xfail(reason="The parser does not check alignment.")
@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_not_aligned(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warns for a single marker not aligned to the completion token."""
    parser.read(dedent(f"""\
          // {marker_type.name}: TEST 0x1234
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # Warning for each line in the sequence.
    assert sorted_alerts(parser) == [
        (AlertCode.MARKER_NOT_ALIGNED, 1),
        (AlertCode.MARKER_NOT_ALIGNED, 2),
    ]


@pytest.mark.xfail(reason="The parser does not check alignment.")
@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_not_aligned_indented(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warns for a single marker not aligned to the completion token
    when both are indented to different levels."""
    parser.read(dedent(f"""\
        class Outer {{
            // {marker_type.name}: TEST 0x1234
          {completion_token(marker_type, annotation_type)}
        }};
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # Warning for each line in the sequence.
    assert sorted_alerts(parser) == [
        (AlertCode.MARKER_NOT_ALIGNED, 2),
        (AlertCode.MARKER_NOT_ALIGNED, 3),
    ]


@pytest.mark.xfail(reason="The parser does not check alignment.")
@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_mixed_whitespace(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warns when the marker and completion token have a different whitespace
    prefix using the same number of characters."""
    parser.read(dedent(f"""\
        class Outer {{
         // {marker_type.name}: TEST 0x1234
        \t{completion_token(marker_type, annotation_type)}
        }};
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # Warning for each line in the sequence.
    assert sorted_alerts(parser) == [
        (AlertCode.MARKER_NOT_ALIGNED, 2),
        (AlertCode.MARKER_NOT_ALIGNED, 3),
    ]


@pytest.mark.xfail(reason="The parser does not check alignment.")
@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_group_first_not_aligned(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warns for a marker group where the first line differs from
    the second and final lines."""
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

    # Warning for each line in the sequence.
    assert sorted_alerts(parser) == [
        (AlertCode.MARKER_NOT_ALIGNED, 1),
        (AlertCode.MARKER_NOT_ALIGNED, 2),
        (AlertCode.MARKER_NOT_ALIGNED, 3),
    ]


@pytest.mark.xfail(reason="The parser does not check alignment.")
@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_group_second_not_aligned(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warns for a marker group where the second line differs from
    the first and final lines."""
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

    # Warning for each line in the sequence.
    assert sorted_alerts(parser) == [
        (AlertCode.MARKER_NOT_ALIGNED, 1),
        (AlertCode.MARKER_NOT_ALIGNED, 2),
        (AlertCode.MARKER_NOT_ALIGNED, 3),
    ]


@pytest.mark.xfail(reason="The parser does not check alignment.")
@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_group_not_aligned_to_token(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warns for a marker group where the final line differs from
    the first and second lines."""
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

    # Warning for each line in the sequence.
    assert sorted_alerts(parser) == [
        (AlertCode.MARKER_NOT_ALIGNED, 1),
        (AlertCode.MARKER_NOT_ALIGNED, 2),
        (AlertCode.MARKER_NOT_ALIGNED, 3),
    ]
