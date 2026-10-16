"""Markers in a sequence that require a completion token must have a compatible type.

If there is a clash of types, all "partial" markers are rejected with an AlertCode.INCOMPATIBLE_MARKER error.

LINE markers do not require a completion token, so they are always accepted.
"""

from textwrap import dedent
import pytest
from reccmp.parser.parser import DecompParser
from reccmp.parser.error import AlertCode
from reccmp.parser.marker import MarkerType
from .parser_helpers import (
    AnnotationType,
    completion_token,
    sorted_alerts,
    symbol_tuples,
)


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    return DecompParser()


# fmt: off
INCOMPATIBLE_TYPES = (
    (MarkerType.FUNCTION, MarkerType.VTABLE),
    (MarkerType.FUNCTION, MarkerType.GLOBAL),
    (MarkerType.FUNCTION, MarkerType.STRING),
    (MarkerType.VTABLE,   MarkerType.FUNCTION),
    (MarkerType.VTABLE,   MarkerType.GLOBAL),
    (MarkerType.VTABLE,   MarkerType.STRING),
    (MarkerType.GLOBAL,   MarkerType.FUNCTION),
    (MarkerType.GLOBAL,   MarkerType.VTABLE),
    (MarkerType.STRING,   MarkerType.FUNCTION),
    (MarkerType.STRING,   MarkerType.VTABLE),
)
# fmt: on


@pytest.mark.parametrize("annotation_type", (AnnotationType.LINE, AnnotationType.NAME))
@pytest.mark.parametrize("first_type, second_type", INCOMPATIBLE_TYPES)
def test_incompatible_type(
    parser: DecompParser,
    first_type: MarkerType,
    second_type: MarkerType,
    annotation_type: AnnotationType,
):
    """Reject all markers that require a completion token if their types are not compatible."""
    parser.read(dedent(f"""\
        // {first_type.name}: TEST 0x1234
        // {second_type.name}: TEST 0x5555
        {completion_token(first_type, annotation_type)}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error for each rejected marker.
    assert sorted_alerts(parser) == [
        (AlertCode.INCOMPATIBLE_MARKER, 1),
        (AlertCode.INCOMPATIBLE_MARKER, 2),
    ]


@pytest.mark.parametrize("first_type, second_type", INCOMPATIBLE_TYPES)
def test_incompatible_type_incomplete(
    parser: DecompParser, first_type: MarkerType, second_type: MarkerType
):
    """Reject all markers that require a completion token if their types are not compatible.
    In this case, there is no valid completion token.
    No markers were accepted, so there are no additional errors."""
    parser.read(dedent(f"""\
        // {first_type.name}: TEST 0x1234
        // {second_type.name}: TEST 0x5555
        ;
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error for each rejected marker.
    assert sorted_alerts(parser) == [
        (AlertCode.INCOMPATIBLE_MARKER, 1),
        (AlertCode.INCOMPATIBLE_MARKER, 2),
    ]


@pytest.mark.parametrize("first_type, second_type", INCOMPATIBLE_TYPES)
def test_incompatible_type_end_of_file(
    parser: DecompParser, first_type: MarkerType, second_type: MarkerType
):
    """Reports each rejected marker, even if the file ends
    before any completion token."""
    parser.read(dedent(f"""\
        // {first_type.name}: TEST 0x1234
        // {second_type.name}: TEST 0x5555
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error for each rejected marker.
    assert sorted_alerts(parser) == [
        (AlertCode.INCOMPATIBLE_MARKER, 1),
        (AlertCode.INCOMPATIBLE_MARKER, 2),
    ]


def test_incompatible_type_repeated(parser: DecompParser):
    """Reports each rejected marker in a sequence with more than one incompatible marker."""
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1234
        // GLOBAL: TEST 0x5555
        // VTABLE: TEST 0x9999
        void test() {}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Error for each rejected marker.
    assert sorted_alerts(parser) == [
        (AlertCode.INCOMPATIBLE_MARKER, 1),
        (AlertCode.INCOMPATIBLE_MARKER, 2),
        (AlertCode.INCOMPATIBLE_MARKER, 3),
    ]


def test_incompatible_type_after_line(parser: DecompParser):
    """The first marker that is not a LINE marker decides the allowed types.
    LINE markers are captured even if the rest of the sequence is rejected."""
    parser.read(dedent("""\
        // LINE: TEST 0x1000
        // GLOBAL: TEST 0x1234
        // FUNCTION: TEST 0x5555
        int g_test = 1;
        """))

    # Captures only the LINE marker.
    assert symbol_tuples(parser) == [
        (MarkerType.LINE, "TEST", 0x1000),
    ]

    # Error for each rejected marker.
    assert sorted_alerts(parser) == [
        (AlertCode.INCOMPATIBLE_MARKER, 2),
        (AlertCode.INCOMPATIBLE_MARKER, 3),
    ]
