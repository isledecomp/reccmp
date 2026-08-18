"""If a marker type is repeated for a target in a marker group,
reject all duplicate markers with an AlertCode.DUPLICATE_MODULE error.
Only the first marker is accepted.

This does not test cases where GLOBAL, STRING, and LINE markers can be combined.

This does not test cases where the various function markers are combined.
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
def test_same_type_different_target(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Accepts markers of the same type from different targets."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        // {marker_type.name}: HELLO 0x5555
        {completion_token(marker_type, annotation_type)}
        """))

    # Captures only the first marker.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]

    # No errors.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_same_type_same_target(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Rejects markers of the same type and target that repeat in a marker group."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        // {marker_type.name}: TEST 0x5555
        {completion_token(marker_type, annotation_type)}
        """))

    # Captures only the first marker.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # Rejects the duplicate marker with an error.
    assert sorted_alerts(parser) == [(AlertCode.DUPLICATE_MODULE, 2)]


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_same_type_same_target_repeated(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Rejects all markers that repeat the type and target of a marker
    earlier in the group."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        // {marker_type.name}: TEST 0x5555
        // {marker_type.name}: TEST 0x9999
        {completion_token(marker_type, annotation_type)}
        """))

    # Captures only the first marker.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # Rejects all duplicate markers with an error.
    assert sorted_alerts(parser) == [
        (AlertCode.DUPLICATE_MODULE, 2),
        (AlertCode.DUPLICATE_MODULE, 3),
    ]


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_same_type_same_target_non_contiguous(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Rejects markers of the same type and target that repeat in a marker group
    even if they are not on consecutive lines."""
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        // {marker_type.name}: HELLO 0x5555
        // {marker_type.name}: TEST 0x5555
        {completion_token(marker_type, annotation_type)}
        """))

    # Captures only the first marker.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]

    # Rejects the duplicate marker with an error.
    assert sorted_alerts(parser) == [(AlertCode.DUPLICATE_MODULE, 3)]


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_aliased_type_same_target(
    marker_type: MarkerType, annotation_type: AnnotationType
):
    """Rejects markers of the same type and target that repeat in a marker group
    even when the first marker uses an alias of the duplicated marker types."""
    parser = DecompParser(aliases={"TEST": {"ALIAS": marker_type.name}})
    parser.read(dedent(f"""\
        // ALIAS: TEST 0x1234
        // {marker_type.name}: TEST 0x5555
        // {marker_type.name}: TEST 0x9999
        {completion_token(marker_type, annotation_type)}
        """))

    # Captures only the first marker.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # Rejects all duplicate markers with an error.
    assert sorted_alerts(parser) == [
        (AlertCode.DUPLICATE_MODULE, 2),
        (AlertCode.DUPLICATE_MODULE, 3),
    ]
