"""Stress tests for the code tokenizer's regex patterns."""

from textwrap import dedent
import pytest
from reccmp.parser.tokenizer import (
    TokenType,
    tokenize_code_file,
)

STRING_VARIANTS = [
    pytest.param('""', id="empty string"),
    pytest.param('L""', id="empty wide string"),
    pytest.param('"test"', id="regular string"),
    pytest.param('L"test"', id="wide string"),
    pytest.param('"// comment"', id="enclosed line comment"),
    pytest.param('"/* comment */"', id="enclosed block comment"),
    pytest.param('"\\""', id="escaped quote"),
    pytest.param('"\\\\"', id="escaped backslash"),
    pytest.param('"\'"', id="single quote inside"),
    pytest.param('"two\\\nlines"', id="string continuation"),
]


@pytest.mark.parametrize("code", STRING_VARIANTS)
def test_string(code: str):
    """Should parse a STRING token and ignore escaped double quotes."""
    assert list(tokenize_code_file(code)) == [(0, len(code), TokenType.STRING)]


CHAR_VARIANTS = [
    pytest.param("''", id="empty char"),
    pytest.param("'x'", id="regular char"),
    pytest.param("L'x'", id="wide char"),
    pytest.param("L''", id="empty wide char"),
    pytest.param("'\\''", id="escaped quote"),
    pytest.param("'\\\\'", id="escaped backslash"),
    pytest.param("'\"'", id="double quote inside"),
    pytest.param("'x\\\ny'", id="string continuation"),
]


@pytest.mark.parametrize("code", CHAR_VARIANTS)
def test_char(code: str):
    """Should parse a CHAR token and ignore escaped single quotes.
    Note: we don't care if the char is more than 1 character."""
    assert list(tokenize_code_file(code)) == [(0, len(code), TokenType.CHAR)]


@pytest.mark.xfail(reason="Edge case")
def test_raw_string():
    """Should parse a C++11 raw string."""
    code = 'R"(test " and })"'
    assert tokenize_code_file(code) == [(0, len(code), TokenType.STRING)]


def test_string_newline_break():
    """Should end a STRING token if the newline is not escaped."""
    assert list(tokenize_code_file('"xx\nyy"')) == [
        (0, 4, TokenType.STRING),
        (4, 7, TokenType.CODE),
    ]


def test_char_newline_break():
    """Should end a CHAR token if the newline is not escaped."""
    assert list(tokenize_code_file("'\nx'")) == [
        (0, 2, TokenType.CHAR),
        (2, 4, TokenType.CODE),
    ]


@pytest.mark.xfail(reason="Edge case")
def test_line_comment_continuation():
    """Should allow line continuation for a line comment."""
    code = dedent("""\
        // First line\\
        Second line""")
    assert tokenize_code_file(code) == [
        (0, 26, TokenType.LINE_COMMENT),
    ]


BLOCK_COMMENT_VARIANTS = [
    pytest.param("/**/", id="empty comment"),
    pytest.param("/* test */", id="block comment"),
    pytest.param("/***/", id="three stars"),
    pytest.param("/* multi \n line \n\n */", id="multi-line block"),
    pytest.param("/* // test */", id="enclosed line comment"),
    pytest.param('/* "test" */', id="enclosed string"),
]


@pytest.mark.parametrize("code", BLOCK_COMMENT_VARIANTS)
def test_block_comment(code: str):
    """Should parse a BLOCK_COMMENT token."""
    assert tokenize_code_file(code) == [(0, len(code), TokenType.BLOCK_COMMENT)]


def test_adjacent_block_comments():
    """Should not combine two block comments into a single token."""
    assert tokenize_code_file("/* a */ /* b */") == [
        (0, 7, TokenType.BLOCK_COMMENT),
        (8, 15, TokenType.BLOCK_COMMENT),
    ]


PPC_IF_VARIANTS = [
    pytest.param("#if A", id="if"),
    pytest.param("#  if A", id="space after hash"),
    pytest.param("#ifdef A", id="ifdef"),
    pytest.param("#ifndef A", id="ifndef"),
    pytest.param('#if A == "x"', id="string in expression"),
    pytest.param("#if A == 'x'", id="char in expression"),
    pytest.param("#if A && \\\n B", id="line continuation"),
]


@pytest.mark.parametrize("code", PPC_IF_VARIANTS)
def test_ppc_if(code: str):
    """Should parse PPC directives that resolve to a PPC_IF token.
    The token includes the expression"""
    assert tokenize_code_file(code) == [(0, len(code), TokenType.PPC_IF)]


PPC_ELIF_VARIANTS = [
    pytest.param("#elif A", id="elif"),
    pytest.param("# elif A", id="space after hash"),
    pytest.param("#elif A || \\\n B", id="line continuation"),
]


@pytest.mark.parametrize("code", PPC_ELIF_VARIANTS)
def test_ppc_elif(code: str):
    """Should parse a PPC_ELIF token."""
    assert tokenize_code_file(code) == [(0, len(code), TokenType.PPC_ELIF)]


PPC_ELSE_VARIANTS = [
    pytest.param("#else", id="else"),
    pytest.param("# else", id="space after hash"),
    pytest.param("#else \\\nint x;", id="line continuation"),
]


@pytest.mark.parametrize("code", PPC_ELSE_VARIANTS)
def test_ppc_else(code: str):
    """Should parse a PPC_ELSE token.
    (Line continuation doesn't make a lot of sense, but it's here to show
    our parsing is consistent across all PPC directives.)"""
    assert tokenize_code_file(code) == [(0, len(code), TokenType.PPC_ELSE)]


PPC_END_VARIANTS = [
    pytest.param("#endif", id="endif"),
    pytest.param("# endif", id="space after hash"),
    pytest.param("#endif \\\nint x;", id="line continuation"),
]


@pytest.mark.parametrize("code", PPC_END_VARIANTS)
def test_ppc_end(code: str):
    """Should parse a PPC_ENDIF token.
    (Line continuation doesn't make a lot of sense, but it's here to show
    our parsing is consistent across all PPC directives.)"""
    assert tokenize_code_file(code) == [(0, len(code), TokenType.PPC_END)]


PPC_OTHER_VARIANTS = [
    pytest.param("#define A 1", id="define"),
    pytest.param('#include "a.h"', id="include quoted"),
    pytest.param("#include <a.h>", id="include brackets"),
    pytest.param("#pragma once", id="pragma"),
    pytest.param("#undef A", id="undef"),
    pytest.param("#define TEST {", id="define with curly bracket"),
    pytest.param("#define XYZ = (while(0) { };)", id="define with many delimiters"),
    pytest.param('#define A "test"', id="define string"),
    pytest.param("#define A 'x'", id="define char"),
    pytest.param('#define A "{"', id="define curly string"),
    pytest.param("#define A '{'", id="define curly char"),
    pytest.param('#define A "//"', id="define line comment string"),
    pytest.param(
        "#define A(x) \\\n    do { x; } while (0)", id="define line continuation"
    ),
    pytest.param("#error nope", id="error"),
    pytest.param("#error don't do this", id="error unmatched single quote"),
    pytest.param('#error "nope"', id="error string"),
]


@pytest.mark.parametrize("code", PPC_OTHER_VARIANTS)
def test_ppc_other(code: str):
    """Should parse non-logical preprocessor directives as PPC_OTHER tokens.
    Should capture the entire expression in the token and not break on delimiters
    or sub-tokens we would otherwise emit."""
    assert tokenize_code_file(code) == [(0, len(code), TokenType.PPC_OTHER)]


@pytest.mark.xfail(reason="Edge case")
def test_block_comment_after_directive():
    """Should consider block comments as line continuations for PPC tokens."""
    assert tokenize_code_file("#define A 1 /*\n*/ + 2") == [
        (0, 21, TokenType.PPC_OTHER),
    ]
