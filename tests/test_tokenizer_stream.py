"""Testing more complex tokenizer behavior, including:

- Handling unexpected EOF
- Gaps between delimiters emitted as CODE tokens
- Context-sensitive handling of ' character
- Determining which tokens include a newline terminator
"""

from itertools import pairwise
from textwrap import dedent
import pytest
from reccmp.parser.tokenizer import (
    TokenType,
    tokenize_code_file,
)

UNFINISHED_TOKENS = [
    pytest.param('"test', id="string"),
    pytest.param("'x", id="char"),
    pytest.param('L"test', id="wide string"),
    pytest.param("/* test", id="block comment"),
]


@pytest.mark.parametrize("code", UNFINISHED_TOKENS)
def test_eof(code: str):
    """Should emit unfinished tokens as CODE."""
    assert list(tokenize_code_file(code)) == [(0, len(code), TokenType.CODE)]


def test_eof_line_comment():
    """A line comment on the last line of the file can be processed normally."""
    code = "// test"
    assert list(tokenize_code_file(code)) == [(0, len(code), TokenType.LINE_COMMENT)]


TRAILING_WHITESPACE_VARIANTS = [
    pytest.param("x;\n", id="newline"),
    pytest.param("x;   ", id="spaces"),
    pytest.param("x;\n\n  \n", id="blank lines"),
]


@pytest.mark.parametrize("code", TRAILING_WHITESPACE_VARIANTS)
def test_trailing_whitespace_at_eof(code: str):
    """Should not emit a CODE token for whitespace at the end of the file."""
    assert tokenize_code_file(code) == [
        (0, 1, TokenType.CODE),
        (1, 2, TokenType.SEMICOLON),
    ]


def test_digit_separator():
    """Should identify a digit separator and not emit a CHAR token."""
    tokens = tokenize_code_file("int x = 1'000'000")
    token_types = [token_type for _, __, token_type in tokens]
    assert TokenType.CHAR not in token_types


def test_digit_separator_naive_skip():
    """Should not drop CODE tokens when a digit separator is detected."""
    assert tokenize_code_file("int x = 1'000; int y = 2'000;") == [
        (0, 5, TokenType.CODE),
        (6, 7, TokenType.EQUAL),
        (8, 13, TokenType.CODE),
        (13, 14, TokenType.SEMICOLON),
        (15, 20, TokenType.CODE),
        (21, 22, TokenType.EQUAL),
        (23, 28, TokenType.CODE),
        (28, 29, TokenType.SEMICOLON),
    ]


@pytest.mark.xfail(reason="Edge case")
def test_char_preceded_by_hex_letter():
    """Should identify that the `e` in `case` does not indicate a hex digit."""
    assert tokenize_code_file("case'}': break;") == [
        (0, 4, TokenType.CODE),
        (4, 7, TokenType.CHAR),
        (7, 14, TokenType.CODE),
        (14, 15, TokenType.SEMICOLON),
    ]


def test_ppc_newline():
    """Tokens should have no gap, except for whitespace."""
    code = dedent("""\
        #ifndef ACT2ACTOR_H
        #define ACT2ACTOR_H

        #include "gogoanimactor.h"
        """)
    tokens = list(tokenize_code_file(code))
    for x, y in pairwise(tokens):
        x_stop = x[1]
        y_start = y[0]
        assert x_stop == y_start or (code[x_stop:y_start].strip() == "")


def test_struct_newline():
    """Tokens should have no gap, except for whitespace."""
    code = dedent("""\
        // SIZE 0x1a8
        class Act2Actor : public TestAnimActor {
        public:
            struct Location {
                MxFloat m_position[3];  // 0x00
                MxFloat m_direction[3]; // 0x0c
                const char* m_boundary; // 0x18
                MxBool m_cleared;       // 0x1c
            };
        """)
    tokens = list(tokenize_code_file(code))
    for x, y in pairwise(tokens):
        x_stop = x[1]
        y_start = y[0]
        assert x_stop == y_start or (code[x_stop:y_start].strip() == "")
