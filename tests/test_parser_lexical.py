"""Testing situations where a "simple" line-based C++ parser fails.
More "complex" lexical parsing is required to avoid unexpected behavior.

For example:
```cpp
/*
// GLOBAL: TEST 0x1234
int g_count = 0;
*/
```

The outer block comment is more significant than the inner line comment.
Parsing the code line-by-line without managing state will cause us to flag the line comment
as a potential reccmp marker.
"""

from textwrap import dedent
import pytest
from reccmp.parser.parser import DecompParser
from reccmp.parser.marker import MarkerType
from .parser_helpers import (
    AnnotationType,
    VALID_ANNOTATIONS,
    completion_token,
    symbol_tuples,
)


@pytest.fixture(name="parser")
def fixture_parser() -> DecompParser:
    return DecompParser()


@pytest.mark.xfail(reason="TODO: #509")
@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_marker_inside_block_comment(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Should ignore the marker on the line inside the block comment."""
    parser.read(dedent(f"""\
        /*
        // {marker_type.name}: TEST 0x1234
        {completion_token(marker_type, annotation_type)}
        */
        """))

    # Captured nothing.
    assert not list(parser.iter_symbols())

    # No warnings.
    assert not parser.alerts


@pytest.mark.xfail(reason="TODO: #509")
@pytest.mark.parametrize("marker_type, annotation_type", VALID_ANNOTATIONS)
def test_marker_with_code_before_the_comment(
    parser: DecompParser, marker_type: MarkerType, annotation_type: AnnotationType
):
    """Should read a marker that is preceded by code on the same line."""
    parser.read(dedent(f"""\
        int x = 1; // {marker_type.name}: TEST 0x1234
        {completion_token(marker_type, annotation_type)}
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # May want to warn here using a new AlertCode.


@pytest.mark.xfail(reason="TODO: #509")
def test_function_end_curly_in_block_comment(parser: DecompParser):
    """Should ignore commented curly brackets when detecting the end of a function."""
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1234
        void test()
        {
            /*
        }
            */
            hello();
        }
        """))

    # Captured the function range accurately.
    (function,) = parser.functions
    assert (function.line_number, function.end_line) == (2, 8)

    # No warnings.
    assert not parser.alerts


@pytest.mark.xfail(reason="TODO: #509")
def test_function_end_curly_in_multiline_string(parser: DecompParser):
    """Should ignore curly brackets inside of strings.
    (This and other examples exploit the fact that curly-bracket matching
    checks the character's horizontal position.)"""
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1234
        void test()
        {
            const char* msg = "\\
        }";
            hello(msg);
        }
        """))

    # Captured the function range accurately.
    (function,) = parser.functions
    assert (function.line_number, function.end_line) == (2, 7)

    # No warnings.
    assert not parser.alerts


@pytest.mark.xfail(reason="TODO: #509")
def test_string_completion_token_line_continuation(parser: DecompParser):
    """Should support strings broken onto multiple lines with a line continuation mark.
    The string text should not include any escaped newlines."""
    parser.read(dedent("""\
        // STRING: TEST 0x1234
        const char* g_msg = "Hello \\
        World";
        """))

    # Captured the correct string text.
    (string,) = parser.strings
    assert string.name == "Hello World"

    # No warnings.
    assert not parser.alerts


@pytest.mark.xfail(reason="TODO: #509")
def test_variable_on_multiple_lines(parser: DecompParser):
    parser.read(dedent("""\
        // GLOBAL: TEST 0x1234
        int
        x
        ;
        """))

    # Captured the marker.
    (symbol,) = parser.iter_symbols()
    assert symbol.type == MarkerType.GLOBAL
    assert symbol.name == "x"

    # No warnings.
    assert not parser.alerts


SPLAYED_TYPES = [
    MarkerType.FUNCTION,
    MarkerType.STUB,
    MarkerType.GLOBAL,
    MarkerType.VTABLE,
]


@pytest.mark.xfail(reason="TODO: #509")
@pytest.mark.parametrize("marker_type", SPLAYED_TYPES)
def test_splayed_line_completion_tokens(parser: DecompParser, marker_type: MarkerType):
    """Should match even when each component of the code completion token is on its own line."""
    token = completion_token(marker_type, AnnotationType.LINE).replace(" ", "\n")
    parser.read(dedent(f"""\
        // {marker_type.name}: TEST 0x1234
        {token}
        """))

    # Captured the marker.
    assert symbol_tuples(parser) == [
        (marker_type, "TEST", 0x1234),
    ]

    # No warnings?
    assert not parser.alerts


def test_struct_keyword_in_variable_type_is_not_scope(parser: DecompParser):
    """Should not add a struct's name to the variable's qualified name
    if the `struct` keyword is part of the variable type.(GH #434)"""
    code = """\
        // GLOBAL: TEST 0x1234
        struct Hello g_test = {{
          1,
        }};
    """
    parser.read(code)

    # Captured the marker.
    (symbol,) = parser.iter_symbols()
    assert symbol.type == MarkerType.GLOBAL

    # Did not qualify the variable name.
    assert "::" not in symbol.name


# MarkerTypes for LINE annotations that can be qualified by a scope.
# Function types are not here because the name we do not make an attempt
# to isolate the function name from its line.
QUALIFIED_TYPES = [
    MarkerType.GLOBAL,
    MarkerType.VTABLE,
]


@pytest.mark.parametrize("marker_type", QUALIFIED_TYPES)
def test_namespace_multiline_comment(parser: DecompParser, marker_type: MarkerType):
    """Should ignore misleading tokens when detecting the range for a named scope."""
    scope_name = "Pizza"
    token = completion_token(marker_type, AnnotationType.LINE)

    # Make sure our scope is not part of the completion token already,
    # because we are not checking the name.
    assert scope_name not in token

    parser.read(f"""\
        namespace {scope_name} {{
        /*
        }}
        */
        // {marker_type.name}: TEST 0x1234
        {token}
        }}
        """)

    # Captured the marker.
    (symbol,) = parser.iter_symbols()
    assert symbol.type == marker_type

    # Qualified the entity name with the outer scope.
    assert scope_name in symbol.name

    # No warnings.
    assert not parser.alerts


@pytest.mark.parametrize("marker_type", QUALIFIED_TYPES)
def test_namespace_multiline_string(parser: DecompParser, marker_type: MarkerType):
    """Should ignore misleading tokens when detecting the range for a named scope."""
    scope_name = "Pizza"
    token = completion_token(marker_type, AnnotationType.LINE)

    # Make sure our scope is not part of the completion token already,
    # because we are not checking the name.
    assert scope_name not in token

    parser.read(f"""\
        namespace {scope_name} {{
        const char *g_text = "}}\\
        }}";
        // {marker_type.name}: TEST 0x1234
        {token}
        }}
        """)

    # Captured the marker.
    (symbol,) = parser.iter_symbols()
    assert symbol.type == marker_type

    # Qualified the entity name with the outer scope.
    assert scope_name in symbol.name

    # No warnings.
    assert not parser.alerts
