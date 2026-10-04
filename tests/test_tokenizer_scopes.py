"""Tests for detecting curly brackets and pairing them to create scopes.

Detecting the name of a class or namespace is tested in test_tokenizer_namespaces.py.
More complex scenarios involving preprocessor directives are in test_tokenizer_scopes_ppc.py.
"""

from reccmp.parser.tokenizer import (
    TokenType,
    tokenize_code_file,
    resolve_scopes,
)


def test_scope_detect_empty():
    """Should not detect any scopes in an empty file."""
    scopes, remain = resolve_scopes(tokenize_code_file(""))
    assert not scopes
    assert not remain


def test_scope_detect_no_usable_tokens():
    """Should not detect any scopes in a file that contains no CURLY token types."""
    tokens = tokenize_code_file('char* test = "my test string"')

    # We parsed the text correctly.
    assert tokens

    # No scopes returned.
    scopes, remain = resolve_scopes(tokens)
    assert not scopes
    assert not remain


def test_scope_detect_single_pair():
    """Should detect a single scope."""
    scopes, remain = resolve_scopes(tokenize_code_file("{}"))
    assert scopes == {0: 1}
    assert not remain


def test_scope_pairs_use_file_position():
    """The values returned in the scope dict represent character positions in the file."""
    code = "class Test {\npublic:\n  Test();\n};"
    start_pos = code.index("{")
    end_pos = code.index("}")

    tokens = tokenize_code_file(code)
    scopes, remain = resolve_scopes(tokens)
    assert scopes == {start_pos: end_pos}
    assert not remain


def test_scope_detect_reverse_pair():
    """Should detect invalid input: curly brackets are in the wrong order.
    The discarded tokens are returned in the `remain` list."""
    scopes, remain = resolve_scopes(tokenize_code_file("}{"))
    assert not scopes
    assert remain == [(0, 1, TokenType.CURLY_CLOSE), (1, 2, TokenType.CURLY_OPEN)]


def test_scope_detect_nested():
    """Should detect nested scopes."""
    scopes, remain = resolve_scopes(tokenize_code_file("{{}}"))
    assert scopes == {0: 3, 1: 2}
    assert not remain


def test_scope_detect_siblings():
    """Should detect two scopes next to each other."""
    scopes, remain = resolve_scopes(tokenize_code_file("{}{}"))
    assert scopes == {0: 1, 2: 3}
    assert not remain


def test_scope_detect_nested_two_levels():
    """Should detect outer scope after pairing both inner scopes."""
    scopes, remain = resolve_scopes(tokenize_code_file("{{}{}}"))
    assert scopes == {0: 5, 1: 2, 3: 4}
    assert not remain


def test_scope_detect_unpaired_close():
    """Unpaired closing bracket returned in the `remain` list."""
    scopes, remain = resolve_scopes(tokenize_code_file("{}}"))
    assert scopes == {0: 1}
    assert remain == [(2, 3, TokenType.CURLY_CLOSE)]


def test_scope_detect_unpaired_open():
    """Should return unpaired opening brackets in the `remain` list."""
    scopes, remain = resolve_scopes(tokenize_code_file("{{}"))
    assert scopes == {1: 2}
    assert remain == [(0, 1, TokenType.CURLY_OPEN)]
