"""Helpers for testing the C++ code parser."""

import enum
import pytest
from reccmp.parser.parser import DecompParser
from reccmp.parser.error import AlertCode
from reccmp.parser.marker import MarkerType


class AnnotationType(enum.Enum):
    LINE = enum.auto()
    NAME = enum.auto()


# fmt: off
# Every marker type that can be completed by a code token.
# Invalid patterns are commented.
LINE_ANNOTATIONS = (
    (MarkerType.FUNCTION,  AnnotationType.LINE),
    (MarkerType.STUB,      AnnotationType.LINE),
    (MarkerType.GLOBAL,    AnnotationType.LINE),
    (MarkerType.STRING,    AnnotationType.LINE),
    (MarkerType.VTABLE,    AnnotationType.LINE),
    # (MarkerType.SYNTHETIC, AnnotationType.LINE),
    # (MarkerType.TEMPLATE,  AnnotationType.LINE),
    # (MarkerType.LIBRARY,   AnnotationType.LINE),
)
# fmt: on

# fmt: off
# Every marker type that can be completed by a comment token.
# Invalid patterns are commented.
NAME_ANNOTATIONS = (
    (MarkerType.FUNCTION,  AnnotationType.NAME),
    # (MarkerType.STUB,      AnnotationType.NAME),
    (MarkerType.GLOBAL,    AnnotationType.NAME),
    (MarkerType.STRING,    AnnotationType.NAME),
    (MarkerType.VTABLE,    AnnotationType.NAME),
    (MarkerType.SYNTHETIC, AnnotationType.NAME),
    (MarkerType.TEMPLATE,  AnnotationType.NAME),
    (MarkerType.LIBRARY,   AnnotationType.NAME),
)
# fmt: on

# All accepted marker type and completion token patterns.
VALID_ANNOTATIONS = (
    *LINE_ANNOTATIONS,
    *NAME_ANNOTATIONS,
)


_FUNCTION_TOKEN = "void function_one() {}"
_VARIABLE_TOKEN = 'char* g_variable = "hello";'
_VTABLE_TOKEN = "class Test {};"


_CODE_COMPLETION_TOKENS = {
    MarkerType.FUNCTION: _FUNCTION_TOKEN,
    MarkerType.STUB: _FUNCTION_TOKEN,
    MarkerType.GLOBAL: _VARIABLE_TOKEN,
    MarkerType.STRING: _VARIABLE_TOKEN,
    MarkerType.VTABLE: _VTABLE_TOKEN,
    # MarkerType.SYNTHETIC: _FUNCTION_TOKEN,
    # MarkerType.TEMPLATE: _FUNCTION_TOKEN,
    # MarkerType.LIBRARY: _FUNCTION_TOKEN,
}


_FUNCTION_NAME = "Test::Function"
_VARIABLE_NAME = "g_variable"
_STRING_NAME = '"hello world"'
_VTABLE_NAME = "class Test"


_COMMENT_COMPLETION_TEXT = {
    MarkerType.FUNCTION: _FUNCTION_NAME,
    # MarkerType.STUB: _FUNCTION_NAME,
    MarkerType.GLOBAL: _VARIABLE_NAME,
    MarkerType.STRING: _STRING_NAME,
    MarkerType.VTABLE: _VTABLE_NAME,
    MarkerType.SYNTHETIC: _FUNCTION_NAME,
    MarkerType.TEMPLATE: _FUNCTION_NAME,
    MarkerType.LIBRARY: _FUNCTION_NAME,
}


def completion_token(
    marker_type: MarkerType,
    annotation_type: AnnotationType,
    *,
    slashes: str = "//",
    name_prefix: str = " ",
    name_suffix: str = "",
) -> str:
    """Returns an example code line or comment that is
    compatible with the given marker type.
    NAME annotations can use an alternate slash prefix and
    alternate whitespace on either side of the name."""
    if annotation_type == AnnotationType.NAME:
        name = _COMMENT_COMPLETION_TEXT[marker_type]
        return f"{slashes}{name_prefix}{name}{name_suffix}"

    return _CODE_COMPLETION_TOKENS[marker_type]


def sorted_alerts(parser: DecompParser) -> list[tuple[AlertCode, int]]:
    """Helper to assert the count of parser warnings and errors along
    with the specific line numbers and alert types (codes).
    The order is not really important because reccmp-decomplint
    applies this same sort before displaying the alert messages."""
    alerts = ((a.code, a.line_number) for a in parser.alerts)
    return sorted(alerts, key=lambda alert: (alert[1], alert[0].value))


def symbol_tuples(parser: DecompParser) -> list[tuple[MarkerType, str, int]]:
    """Returns (marker_type, reccmp_target, address) of each marker captured by the parser.
    This is intended for tests that parametrize on VALID_ANNOTATIONS to assert that
    we have accepted or rejected the markers in the code sample."""
    return [(s.type, s.module, s.offset) for s in parser.iter_symbols()]


def xfail_param(*value, reason: str = ""):
    return pytest.param(*value, marks=pytest.mark.xfail(reason=reason))
