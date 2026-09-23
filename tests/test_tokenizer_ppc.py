"""Tests for evaluating the preprocessor (PPC) expressions that we can: 0 or 1.
Should evaluate fully in a single pass. (i.e. do not evaluate only one nesting layer)
The returned tokens must contain valid PPC blocks. Do not start a block with ELIF when we
have removed preceding PPC tokens."""

from textwrap import dedent
import pytest
from reccmp.parser.tokenizer import (
    CodeToken,
    TokenType,
    resolve_preprocessor,
    tokenize_code_file,
)


def replace_token_type(token: CodeToken, token_type: TokenType) -> CodeToken:
    """Return a new token with a replaced type. Used for idiomatic #elif -> #if replacement."""
    return (token[0], token[1], token_type)


###
###
### Tests with non-constant PPC expressions only.
###
###


def test_identity():
    """No PPC tokens in the input: do not modify."""
    code = dedent("""\
        // Test Function
        void test() {
            example();
        }
    """)
    tokens = tokenize_code_file(code)
    assert resolve_preprocessor(tokens, code) == tokens


def test_if_expr():
    """Cannot evaluate the PPC expression: do not modify."""
    code = dedent("""\
        #if X
        A
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert resolve_preprocessor(tokens, code) == tokens


def test_if_expr_else():
    """Cannot evaluate the PPC expression with #else: do not modify."""
    code = dedent("""\
        #if X
        A
        #else
        B
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert resolve_preprocessor(tokens, code) == tokens


def test_if_expr_elif():
    """Cannot evaluate either PPC expression: do not modify."""
    code = dedent("""\
        #if X
        A
        #elif Y
        B
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert resolve_preprocessor(tokens, code) == tokens


###
###
### Tests for isolating constant expressions from other sub-tokens.
###
###


def test_if_0_line_comment():
    """Show recognize `#if 0` with a trailing line comment."""
    code = dedent("""\
        #if 0 // comment
        A
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert not resolve_preprocessor(tokens, code)


@pytest.mark.xfail(reason="Intentional limits of current design.")
def test_if_0_block_comment():
    """Show recognize `#if 0` with a trailing block comment."""
    code = dedent("""\
        #if 0 /* comment */
        A
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert not resolve_preprocessor(tokens, code)


###
###
### Tests for evaluating expressions that resolve to constants.
###
###


CONSTANT_EXPRESSIONS_FALSE = [
    ("0 && 1", False),
    ("1 && 0", False),
    ("0 && X", False),
    ("X && 0", False),
]


@pytest.mark.parametrize("expression", CONSTANT_EXPRESSIONS_FALSE)
@pytest.mark.xfail(reason="Intentional limits of current design.")
def test_constant_expression_false(expression: str):
    """Should evaluate preprocessor expressions that reduce to a constant false."""
    code = dedent(f"""\
        #if {expression}
        A
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert not resolve_preprocessor(tokens, code)


CONSTANT_EXPRESSIONS_TRUE = [
    ("0 || 1"),
    ("1 || 0"),
    ("1 || X"),
    ("X || 1"),
]


@pytest.mark.parametrize("expression", CONSTANT_EXPRESSIONS_TRUE)
def test_constant_expression_true(expression: str):
    """Should evaluate preprocessor expressions that reduce to a constant true."""
    code = dedent(f"""\
        #if {expression}
        A
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert resolve_preprocessor(tokens, code)


###
###
### Tests with constant PPC expressions, no nesting.
###
###


def test_if_0():
    """`#if 0`: remove all tokens in the block."""
    code = dedent("""\
        #if 0
        A
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert not resolve_preprocessor(tokens, code)


def test_if_0_else():
    """`#if 0` with #else: keep the #else body only, remove PPC tokens."""
    code = dedent("""\
        #if 0
        A
        #else
        B
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(0), CODE(A), PPC_ELSE, CODE(B), PPC_END]
    assert resolve_preprocessor(tokens, code) == [tokens[3]]


def test_if_0_elif():
    """`#if 0` followed by #elif: rewrite the #elif to #if
    so we have a valid PPC block for future processing."""
    code = dedent("""\
        #if 0
        A
        #elif X
        B
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(0), CODE(A), PPC_ELIF(X), CODE(B), PPC_END]
    assert resolve_preprocessor(tokens, code) == [
        replace_token_type(tokens[2], TokenType.PPC_IF),
        tokens[3],
        tokens[4],
    ]


def test_if_1():
    """`#if 1`: remove PPC tokens, keep the inner tokens."""
    code = dedent("""\
        #if 1
        A
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(1), CODE(A), PPC_END]
    assert resolve_preprocessor(tokens, code) == [tokens[1]]


def test_if_1_else():
    """`#if 1` with #else: keep the #if body only."""
    code = dedent("""\
        #if 1
        A
        #else
        B
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert resolve_preprocessor(tokens, code) == [tokens[1]]


def test_if_1_elif():
    """`#if 1` followed by #elif: keep the #if body only."""
    code = dedent("""\
        #if 1
        A
        #elif X
        B
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert resolve_preprocessor(tokens, code) == [tokens[1]]


def test_if_expr_elif_0():
    """`#if (expr)` followed by `#elif 0`: drop the second leg, retain PPC wrapper."""
    code = dedent("""\
        #if X
        A
        #elif 0
        B
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(X), CODE(A), PPC_ELIF(0), CODE(B), PPC_END]
    assert resolve_preprocessor(tokens, code) == [tokens[0], tokens[1], tokens[4]]


def test_if_expr_elif_1():
    """`#if (expr)` followed by `#elif 1`: the `1` leg is only chosen when `X` is false.
    Because we cannot evaluate `X`, do not alter the input tokens."""
    code = dedent("""\
        #if X
        A
        #elif 1
        B
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert resolve_preprocessor(tokens, code) == tokens


def test_if_expr_elif_1_else():
    """`#elif 1` followed by `#else`: drop the redundant `#else`, keep the rest."""
    code = dedent("""\
        #if X
        A
        #elif 1
        B
        #else
        C
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(X), CODE(A), PPC_ELIF(1), CODE(B), PPC_ELSE, CODE(C), PPC_END]
    assert resolve_preprocessor(tokens, code) == [
        tokens[0],
        tokens[1],
        tokens[2],
        tokens[3],
        tokens[6],
    ]


def test_if_expr_elif_expr_elif_1():
    """Expanded version of `test_if_expr_elif_1` with more options.
    The final `#else` branch is made redundant by the preceding `#elif 1`.
    No other modifications are possible."""
    code = dedent("""\
        #if X
        A
        #elif Y
        B
        #elif 1
        C
        #else
        D
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(X), CODE(A), PPC_ELIF(Y), CODE(B), PPC_ELIF(1), CODE(C), PPC_ELSE, CODE(D), PPC_END]
    assert resolve_preprocessor(tokens, code) == [*tokens[:6], tokens[8]]


def test_if_0_elif_0():
    """`#if 0` followed by `#elif 0`: no tokens remain."""
    code = dedent("""\
        #if 0
        A
        #elif 0
        B
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert not resolve_preprocessor(tokens, code)


def test_if_0_elif_0_elif_expr():
    """Should eliminate two consecutive `#if 0` branches
    and promote the last `#elif` to `#if`."""
    code = dedent("""\
        #if 0
        A
        #elif 0
        B
        #elif X
        C
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(0), CODE(A), PPC_ELIF(0), CODE(B), PPC_ELIF(X), CODE(C), PPC_END]
    assert resolve_preprocessor(tokens, code) == [
        replace_token_type(tokens[4], TokenType.PPC_IF),
        tokens[5],
        tokens[6],
    ]


def test_if_0_elif_expr_else():
    """`#if 0` with both #elif and #else: rewrite the #elif, keep the rest."""
    code = dedent("""\
        #if 0
        A
        #elif X
        B
        #else
        C
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(0), CODE(A), PPC_ELIF(X), CODE(B), PPC_ELSE, CODE(C), PPC_END]
    assert resolve_preprocessor(tokens, code) == [
        replace_token_type(tokens[2], TokenType.PPC_IF),
        tokens[3],
        tokens[4],
        tokens[5],
        tokens[6],
    ]


def test_if_0_elif_0_else():
    """Should unwrap the `#else` option after removing the two preceding dead options."""
    code = dedent("""\
        #if 0
        A
        #elif 0
        B
        #else
        C
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(0), CODE(A), PPC_ELIF(0), CODE(B), PPC_ELSE, CODE(C), PPC_END]
    assert resolve_preprocessor(tokens, code) == [tokens[5]]


def test_if_0_elif_1_else():
    """Should select the `#elif 1` option because it is first after the discarded `#if 0`."""
    code = dedent("""\
        #if 0
        A
        #elif 1
        B
        #else
        C
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(0), CODE(A), PPC_ELIF(1), CODE(B), PPC_ELSE, CODE(C), PPC_END]
    assert resolve_preprocessor(tokens, code) == [tokens[3]]


###
###
### Tests with simple nesting
###
###


def test_if_expr_nested_if_0():
    """Remove inner `#if 0`, keep the outer `#if (expr)` wrapper and inner token."""
    code = dedent("""\
        #if X
        A
        #if 0
        B
        #endif
        C
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(X), CODE(A), PPC_IF(0), CODE(B), PPC_END, CODE(C), PPC_END]
    assert resolve_preprocessor(tokens, code) == [
        tokens[0],
        tokens[1],
        tokens[5],
        tokens[6],
    ]


def test_if_expr_nested_if_1():
    """Unwrap the inner `#if 1` block, keep the outer `#if (expr)` wrapper."""
    code = dedent("""\
        #if X
        A
        #if 1
        B
        #endif
        C
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(X), CODE(A), PPC_IF(1), CODE(B), PPC_END, CODE(C), PPC_END]
    assert resolve_preprocessor(tokens, code) == [
        tokens[0],
        tokens[1],
        tokens[3],
        tokens[5],
        tokens[6],
    ]


def test_if_0_nested_if_1():
    """The outer `#if 0` removes all tokens, despite the inner `#if 1`."""
    code = dedent("""\
        #if 0
        A
        #if 1
        B
        #endif
        C
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert not resolve_preprocessor(tokens, code)


def test_if_1_nested_if_0():
    """Remove inner `#if 0`, unwrap outer `#if 1`."""
    code = dedent("""\
        #if 1
        A
        #if 0
        B
        #endif
        C
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(1), CODE(A), PPC_IF(0), CODE(B), PPC_END, CODE(C), PPC_END]
    assert resolve_preprocessor(tokens, code) == [tokens[1], tokens[5]]


def test_if_0_nested_if_blocks():
    """Outer `#if 0` removes any inner tokens, regardless of PPC expression."""
    code = dedent("""\
        #if 0
        #if 1
        A
        #endif
        #if X
        B
        #endif
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert not resolve_preprocessor(tokens, code)


##
##
## Tests with complex nesting (multiple options)
##
##


def test_if_0_nested_if_0_else():
    """The inner #else handling should not override the outer `#if 0`."""
    code = dedent("""\
        #if 0
        #if 0
        A
        #else
        B
        #endif
        #endif
    """)
    tokens = tokenize_code_file(code)
    assert not resolve_preprocessor(tokens, code)


def test_if_0_elif_expr_with_nested_if_1():
    """`#if 0` followed by #elif. The first option is removed despite its inner `#if 1`.
    Should rewrite the #elif token to create a valid PPC block."""
    code = dedent("""\
        #if 0
        #if 1
        A
        #endif
        #elif X
        B
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(0), PPC_IF(1), CODE(A), PPC_END, PPC_ELIF(X), CODE(B), PPC_END]
    assert resolve_preprocessor(tokens, code) == [
        replace_token_type(tokens[4], TokenType.PPC_IF),
        tokens[5],
        tokens[6],
    ]


def test_if_0_else_nested_if_0_else():
    """Should unwrap to the only valid option in a single pass."""
    code = dedent("""\
        #if 0
        A
        #else
        #if 0
        B
        #else
        C
        #endif
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(0), CODE(A), PPC_ELSE, PPC_IF(0), CODE(B), PPC_ELSE, CODE(C), PPC_END, PPC_END]
    assert resolve_preprocessor(tokens, code) == [tokens[6]]


def test_if_1_nested_if_0_else_with_else():
    """Should unwrap to the only valid option in a single pass."""
    code = dedent("""\
        #if 1
        #if 0
        A
        #else
        B
        #endif
        #else
        C
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(1), PPC_IF(0), CODE(A), PPC_ELSE, CODE(B), PPC_END, PPC_ELSE, CODE(C), PPC_END]
    assert resolve_preprocessor(tokens, code) == [tokens[4]]


def test_three_levels_of_nesting():
    """Should handle PPC nesting of any depth in one pass."""
    code = dedent("""\
        #if 1
        #if 1
        #if 0
        A
        #else
        B
        #endif
        #endif
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(1), PPC_IF(1), PPC_IF(0), CODE(A), PPC_ELSE, CODE(B), PPC_END, PPC_END, PPC_END]
    assert resolve_preprocessor(tokens, code) == [tokens[5]]


def test_if_expr_elif_0_nested():
    """Should correctly handle nested elimination and consecutive #endif tokens."""
    code = dedent("""\
        #if X
        A
        #elif 0
        #if Y
        B
        #endif
        #endif
    """)
    tokens = tokenize_code_file(code)
    # tokens: [PPC_IF(X), CODE(A), PPC_ELIF(0), PPC_IF(Y), CODE(B), PPC_END, PPC_END]
    assert resolve_preprocessor(tokens, code) == [
        tokens[0],
        tokens[1],
        tokens[6],
    ]
