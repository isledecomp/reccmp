"""All lines in a marker sequence must have the same number of frontslash
characters, including the completion token for a nameref annotation.

If there is any disagreement, record AlertCode.VARYING_SLASH_DEPTH for each comment line.
"""

from textwrap import dedent
import pytest
from reccmp.parser.parser import DecompParser
from reccmp.parser.error import AlertCode
from reccmp.parser.marker import MarkerType
from .parser_helpers import (
    AnnotationType,
    LINE_ANNOTATIONS,
    NAME_ANNOTATIONS,
    VALID_ANNOTATIONS,
    completion_token,
    sorted_alerts,
    symbol_tuples,
    xfail_param,
)


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    return DecompParser()


SLASH_VARIANTS = [
    "//",
    xfail_param("///", reason="Not identified as marker."),
    xfail_param("////", reason="Not identified as marker."),
]


@pytest.mark.parametrize("slashes", SLASH_VARIANTS)
@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_slash_agreement(
    parser: DecompParser,
    marker_type: MarkerType,
    annotation_type: AnnotationType,
    slashes: str,
):
    """Markers and completion tokens can have more than two slashes
    if all lines have the same number."""
    parser.read(dedent(f"""\
        {slashes} {marker_type.name}: TEST 0x1234
        {slashes} {marker_type.name}: HELLO 0x5555
        {completion_token(marker_type, annotation_type, slashes=slashes)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]

    # No warning.
    assert not parser.alerts


# fmt: off
LINE_SLASH_VARIANTS = [
    ("//",   "///"),
    ("///",  "//"),
    ("///",  "////"),
]
# fmt: on


@pytest.mark.xfail(reason="The parser does not check slashes.")
@pytest.mark.parametrize("slashes", LINE_SLASH_VARIANTS)
@pytest.mark.parametrize("marker_type, annotation_type", LINE_ANNOTATIONS)
def test_slash_depth_mismatch_code(
    parser: DecompParser,
    marker_type: MarkerType,
    annotation_type: AnnotationType,
    slashes: tuple[str, str],
):
    """The slashes for the two markers do not agree.
    Each marker is accepted, but with a VARYING_SLASH_DEPTH warning."""
    first, second = slashes
    parser.read(dedent(f"""\
        {first} {marker_type.name}: TEST 0x1234
        {second} {marker_type.name}: HELLO 0x5555
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]

    # Warnings for each comment line.
    # No warning for the code completion token.
    assert sorted_alerts(parser) == [
        (AlertCode.VARYING_SLASH_DEPTH, 1),
        (AlertCode.VARYING_SLASH_DEPTH, 2),
    ]


# fmt: off
NAME_SLASH_VARIANTS = [
    ("//",  "//",  "///"),
    ("///", "//",  "//"),
    ("///", "//",  "////"),
    # more?
]
# fmt: on


@pytest.mark.xfail(reason="The parser does not check slashes.")
@pytest.mark.parametrize("slashes", NAME_SLASH_VARIANTS)
@pytest.mark.parametrize("marker_type, annotation_type", NAME_ANNOTATIONS)
def test_slash_depth_mismatch_nameref(
    parser: DecompParser,
    marker_type: MarkerType,
    annotation_type: AnnotationType,
    slashes: tuple[str, str, str],
):
    """The slashes for the two markers and the completion token do not agree.
    All three lines get a VARYING_SLASH_DEPTH warning."""
    first, second, third = slashes
    parser.read(dedent(f"""\
        {first} {marker_type.name}: TEST 0x1234
        {second} {marker_type.name}: HELLO 0x5555
        {completion_token(marker_type, annotation_type, slashes=third)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "HELLO", 0x5555),
    ]

    # Warnings for each comment line.
    assert sorted_alerts(parser) == [
        (AlertCode.VARYING_SLASH_DEPTH, 1),
        (AlertCode.VARYING_SLASH_DEPTH, 2),
        (AlertCode.VARYING_SLASH_DEPTH, 3),
    ]
