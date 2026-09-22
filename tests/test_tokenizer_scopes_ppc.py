"""Tests for pairing curly brackets where we need to consider preprocessor directives.

We cannot evaluate the PPC expressions, so we are limited to tweaks that do not require evaluation.
"""

from textwrap import dedent
import pytest
from reccmp.parser.tokenizer import (
    TokenType,
    tokenize_code_file,
    resolve_scopes,
)


def test_handle_invalid_ppc():
    """Should not crash if the input has an invalid PPC sequence."""
    code = "#endif"
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not scopes


def test_equal_bracket_sequence():
    """Should reduce a PPC block with equal bracket sequences across all its branches."""
    code = dedent("""\
        #ifdef COMPAT_MODE
        {
        #else
        {
        #endif
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)

    # Should choose the bracket from `#ifdef COMPAT_MODE` to pair with the outer bracket.
    assert scopes == {19: 36}


def test_equal_bracket_sequence_wrapped():
    """Should reduce a PPC block with equal bracket sequences across all its branches.
    In this example, there is an extra bracket pair wrapping the sequence."""
    code = dedent("""\
        {
        #ifdef COMPAT_MODE
        {
        #else
        {
        #endif
        }
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)

    # Should pair the outermost brackets.
    # Should pair the bracket inside `#ifdef COMPAT_MODE` with the one after the `#endif`.
    assert scopes == {0: 40, 21: 38}


def test_unequal_bracket_sequence():
    """Should not reduce the PPC block because its branches have unequal bracket sequences."""
    code = dedent("""\
        #ifdef COMPAT_MODE
        {
        #else
        #endif
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not scopes


def test_unequal_bracket_sequence_wrapped():
    """Should not reduce the PPC block because its branches have unequal bracket sequences.
    This conflict blocks the potential pairing of the two outermost brackets."""
    code = dedent("""\
        {
        #ifdef COMPAT_MODE
        {
        #else
        #endif
        }
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not scopes


def test_extern_c():
    """Should pair brackets split across multiple PPC sequences.
    This is possible as long as the remaining brackets are "globally" balanced."""
    code = dedent("""\
        #ifdef TEST
        extern "C" {
        #endif
        
        #ifdef TEST
        }
        #endif
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert scopes == {23: 45}


def test_extern_c_without_balance():
    """Should not pair brackets in this example.
    Enabling all PPC sequences is not possible because there is a "global" imbalance of brackets.
    """
    code = dedent("""\
        #ifdef TEST
        extern "C" {
        #endif
        {
        #ifdef TEST
        }
        #endif
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not scopes


def test_equal_bracket_sequence_with_elif():
    """Should reduce a PPC block with equal bracket sequences across any number of branches."""
    code = dedent("""\
        {
        #if A
        {
        #elif B
        {
        #elif C
        {
        #endif
        }
        }
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {0: 39, 8: 37}
    assert not remain


def test_nested_ifs():
    """Should pair brackets from nested #if blocks.
    This is possible because enabling all PPC branches results in a global balance of brackets.
    """
    code = dedent("""\
        #if A
        {
        # if B
        {
        # endif
        }
        #endif
        }
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {6: 34, 15: 25}
    assert not remain


def test_equal_bracket_sequence_with_multiple_brackets():
    """Should reduce a PPC block with equal bracket sequence regardless of the number of brackets used."""
    code = dedent("""\
        {{
        #if A
        {{
        #else
        {{
        #endif
        }}
        }}
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {0: 32, 1: 31, 9: 29, 10: 28}
    assert not remain


def test_ppc_branch_with_internal_balance():
    """Should pair brackets inside of PPC branches.
    We do not evaluate the PPC expression so we cannot determine whether the brackets _should_ be enabled.
    """
    code = dedent("""\
        #if A
        {
        }
        #else
        #endif
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {6: 8}
    assert not remain


def test_ppc_branches_with_internal_balance():
    """Should pair brackets inside of any PPC branch, even when enabling tokens from competing branches
    should be impossible."""
    code = dedent("""\
        #if A
        {
        }
        #else
        {
        }
        #endif
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {6: 8, 16: 18}

    # Should not return any leftover tokens because we can find a "clean" pairing for all brackets.
    assert not remain


def test_pairing_results_in_equal_branches_1():
    """Should pair brackets from the `A` branch first, then combine the `A` and `!A` branches.
    This is possible because pairing the adjoining brackets from `A` results in an equal bracket sequence.
    """
    code = dedent("""\
        #if A
        {
        }
        {
        #else
        {
        #endif
        }
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {6: 8, 10: 27}
    assert not remain


def test_pairing_results_in_equal_branches_2():
    """Should pair brackets from the `!A` branch first, then combine the `A` and `!A` branches.
    This is possible because pairing the adjoining brackets from `!A` results in an equal bracket sequence.
    This example demonstrates a facet of our pairing behavior that may seem odd.
    We emit a pair from `!A`, but use a bracket from the opposing branch `A` to pair with the outermost bracket.
    """
    code = dedent("""\
        #if A
        {
        #else
        {
        }
        {
        #endif
        }
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))
    assert scopes == {6: 27, 14: 16}
    assert not remain


def test_unequal_bracket_directions():
    """Should not reduce the PPC block because its branches have unequal bracket sequences.
    (This demonstrates that we check more than just the number of CURLY tokens per branch.)
    """
    code = dedent("""\
        {
        #ifdef TEST
        {
        #else
        }
        #endif
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not scopes


def test_unequal_bracket_sequence_with_obvious_choice():
    """Should not enable brackets from `A` even though it is the only branch that will result in global bracket balance."""
    code = dedent("""\
        {
        #if A
        {
        {
        #else
        {
        #endif
        }
        }
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not scopes


def test_unequal_bracket_sequence_with_majority_choice():
    """Should not reduce the PPC block because its branches have unequal bracket sequences.
    Here two branches disagree with a third, but we do not take any action."""
    code = dedent("""\
        {
        #if A
        {
        #elif B
        {
        #elif C
        }
        #endif
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert not scopes


def test_cannot_resolve_without_evaluation():
    """Should not return any bracket pairs. We cannot evaluate `TEST`, so the PPC blocks prevents
    us from pairing the two outermost brackets."""
    code = dedent("""\
        {
        #ifdef TEST
        {
        #endif
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not scopes


@pytest.mark.xfail(reason="TODO: #509. Limited PPC evaluation is not enabled yet.")
def test_evaluate_if_0():
    """Should remove the tokens from a PPC expression we can evaluate, then return the valid bracket pair."""
    code = dedent("""\
        {
        #if 0
        {
        #endif
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert scopes


def test_equal_bracket_sequence_without_global_balance_1():
    """Should reject a naive pairing that enables all PPC branches.
    `A` and `!A` would both be active, which is impossible.
    Here the PPC block contains the _closing_ brackets.
    Combine the equivalent bracket sequences from `A` and `!A` to return one valid pairing.
    """
    code = dedent("""\
        {
        {
        #if A
        }
        #else
        }
        #endif
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))

    # Should pair the second bracket in the file to the adjacent bracket from `A`.
    assert scopes == {2: 10}

    # Return the first bracket in the file as unpaired.
    assert remain == [(0, 1, TokenType.CURLY_OPEN)]


def test_equal_bracket_sequence_without_global_balance_2():
    """Should reject a naive pairing that enables all PPC branches.
    `A` and `!A` would both be active, which is impossible.
    Here the PPC block contains the _opening_ brackets.
    Combine the equivalent bracket sequences from `A` and `!A` to return one valid pairing.
    """
    code = dedent("""\
        #if A
        {
        #else
        {
        #endif
        }
        }
    """)
    scopes, remain = resolve_scopes(tokenize_code_file(code))

    # Should use the first bracket from the `A` branch to pair.
    assert scopes == {6: 23}

    # Return the last bracket in the file as unpaired.
    assert remain == [(25, 26, TokenType.CURLY_CLOSE)]


@pytest.mark.xfail(reason="Returns nothing for this invalid input.")
def test_option_to_salvage_valid_pairing():
    """Should return partial bracket pairing for invalid input.
    In this case, it is the pair split by `#ifdef X`.
    If we isolate the invalid input, we can remove the `#ifdef Y` block and create a second pair.
    """
    code = dedent("""\
        {
        #ifdef X
        #endif
        }
        {
        #ifdef Y
        {
        #else
        }
        #endif
        }
    """)
    scopes, _ = resolve_scopes(tokenize_code_file(code))
    assert scopes == {0: 18}
