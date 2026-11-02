"""Errors that apply to the whole file rather than to a specific marker."""

from textwrap import dedent
import pytest
from reccmp.parser.error import AlertCode
from reccmp.parser.parser import DecompParser
from reccmp.parser.marker import MarkerType
from .parser_helpers import (
    sorted_alerts,
    symbol_tuples,
)


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    return DecompParser()


def test_bracket_imbalance(parser: DecompParser):
    """Should report global bracket imbalance regardless of whether any markers were affected."""
    parser.read(dedent("""\
        }}
        // FUNCTION: TEST 0x1234
        void test() {{}}
    """))

    # Captured all markers.
    assert symbol_tuples(parser) == [(MarkerType.FUNCTION, "TEST", 0x1234)]

    # Error for bracket imbalance.
    assert sorted_alerts(parser) == [
        (AlertCode.CURLY_BRACKET_IMBALANCE, 1),
    ]
