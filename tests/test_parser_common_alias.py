"""The parser accepts aliases to built-in marker types, scoped by target.
The alias behaves exactly the same as the original marker type.
The original marker type can still be used.
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

ALIAS_NAME = "ALIAS"
"""n.b. The alias string has already been normalized by normalize_project_aliases()
by this point, so it must be upper-case."""


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_no_aliases(marker_type: MarkerType, annotation_type: AnnotationType):
    """Warns about an unrecognized marker regardless of completion token."""
    parser = DecompParser()
    parser.read(dedent(f"""\
        // {ALIAS_NAME}: TEST 0x1234
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured nothing.
    assert not symbol_tuples(parser)

    # Warning for the unknown marker type.
    assert sorted_alerts(parser) == [(AlertCode.UNKNOWN_ANNOTATION, 1)]


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_alias(marker_type: MarkerType, annotation_type: AnnotationType):
    """Accepts an alias for all valid annotation types."""
    parser = DecompParser(aliases={"TEST": {ALIAS_NAME: marker_type.name}})
    parser.read(dedent(f"""\
        // {ALIAS_NAME}: TEST 0x1234
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    # The alias does not persist beyond the parsing step.
    # By all accounts, this is whatever marker type was aliased.
    assert symbol_tuples(parser) == [(marker_type, "TEST", 0x1234)]

    # No warnings.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_alias_and_original(marker_type: MarkerType, annotation_type: AnnotationType):
    """Accepts both the alias and the original marker type."""
    parser = DecompParser(aliases={"TEST": {ALIAS_NAME: marker_type.name}})
    parser.read(dedent(f"""\
        // {ALIAS_NAME}: TEST 0x1234
        {completion_token(marker_type, annotation_type)}

        // {marker_type.name}: TEST 0x5555
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
        (marker_type, "TEST", 0x5555),
    ]

    # No warnings.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_alias_not_exact_syntax(
    marker_type: MarkerType, annotation_type: AnnotationType
):
    """Warns when an alias does not match expected syntax."""
    parser = DecompParser(aliases={"TEST": {ALIAS_NAME: marker_type.name}})
    parser.read(dedent(f"""\
        // {ALIAS_NAME.lower()}: TEST 0x1234
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured all markers.
    assert symbol_tuples(parser) == [(marker_type, "TEST", 0x1234)]

    # Syntax warning.
    assert sorted_alerts(parser) == [(AlertCode.NOT_STRICT_FORMAT, 1)]


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_alias_other_target(marker_type: MarkerType, annotation_type: AnnotationType):
    """Ignores an alias that belongs to a different target."""
    parser = DecompParser(aliases={"TEST": {ALIAS_NAME: marker_type.name}})
    parser.read(dedent(f"""\
        // {ALIAS_NAME}: TEST 0x1234
        // {ALIAS_NAME}: HELLO 0x1234
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured markers for the "TEST" target.
    assert symbol_tuples(parser) == [(marker_type, "TEST", 0x1234)]

    # Warning for the "HELLO" target which does not have an alias.
    assert sorted_alerts(parser) == [(AlertCode.UNKNOWN_ANNOTATION, 2)]


@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_alias_chain(marker_type: MarkerType, annotation_type: AnnotationType):
    """Does not follow an alias that points at another alias."""
    parser = DecompParser(
        aliases={"TEST": {"HELLO": ALIAS_NAME, ALIAS_NAME: marker_type.name}}
    )
    parser.read(dedent(f"""\
        // {ALIAS_NAME}: TEST 0x1234
        {completion_token(marker_type, annotation_type)}

        // HELLO: TEST 0x5555
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured only the marker that aliased the built-in type.
    assert symbol_tuples(parser) == [(marker_type, "TEST", 0x1234)]

    # Warning for the double alias marker.
    assert sorted_alerts(parser) == [(AlertCode.UNKNOWN_ANNOTATION, 4)]
