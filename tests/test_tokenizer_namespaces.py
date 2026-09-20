"""Tests for extracting the namespace/struct/class name attached to a scope."""

from textwrap import dedent
import pytest
from reccmp.parser.tokenizer import (
    tokenize_code_file,
    get_namespaces_from_scopes,
    resolve_scopes,
)


@pytest.mark.parametrize("prefix", ["struct", "class", "namespace"])
def test_namespace_prefix(prefix: str):
    """Should extract the namespace from any of the three allowed prefixes."""
    code = dedent(f"""\
        {prefix} Test {{
        int g_test;
        }}
    """)

    # The exact position varies with the prefix used.
    start_pos = code.index("{")
    end_pos = code.index("}")

    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [
        (start_pos, end_pos, "Test")
    ]


def test_class_with_base():
    """Should correctly extract the namespace name from a class with a list of base classes."""
    code = dedent("""\
        class Test : public Other {
        int m_test;
        };
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [(26, 40, "Test")]


def test_forward_reference():
    """Should not declare a namespace for a class or struct without curly brackets."""
    code = dedent("""\
        class Test;
        struct Other;
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not get_namespaces_from_scopes(code, tokens, scopes)


def test_nested_scopes():
    """Should report the list of scopes in the order they begin in the file.
    (i.e. sorted by start position.)"""
    code = dedent("""\
        namespace Test {
        struct Inner {
        int m_test;
        };
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [
        (15, 47, "Test"),
        (30, 44, "Inner"),
    ]


def test_access_specifier_before_declaration():
    """Should read the name after the keyword and not the access specifier
    on the same line."""
    code = dedent("""\
        class Test {
        public: struct Inner {
        int m_test;
        };
        };
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [
        (11, 51, "Test"),
        (34, 48, "Inner"),
    ]


def test_unmatched_brackets():
    """Should not declare a scope for an unpaired curly bracket."""
    code = dedent("""\
        class Test {
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not get_namespaces_from_scopes(code, tokens, scopes)


def test_ignore_control_flow():
    """Should not define a namespace for scopes that are not a class, struct, or namespace."""
    code = dedent("""\
        if (test) {
        }
        for (;;) {
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not get_namespaces_from_scopes(code, tokens, scopes)


def test_elaborated_type_in_function_argument():
    """Should not define a namespace for a function body when an argument
    uses the `struct` keyword."""
    code = dedent("""\
        void Test(struct Other* p) {
        int m_test;
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not get_namespaces_from_scopes(code, tokens, scopes)


def test_no_space_before_curly():
    """Should detect the scope name next to the curly bracket."""
    code = dedent("""\
        namespace Test{
        int g_test;
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [(14, 28, "Test")]


def test_keyword_in_comment():
    """Should ignore a comment that resembles a class declaration."""
    code = dedent("""\
        // Helper for class Renderer
        void test()
        {
        int g_test;
        }
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not get_namespaces_from_scopes(code, tokens, scopes)


def test_declaration_after_comment_keyword():
    """Should use the declaration nearest to the scope, not the one in the comment."""
    code = dedent("""\
        /* class Renderer */ class Test {
        int m_test;
        };
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [(32, 46, "Test")]


def test_base_class_declaration_splayed():
    """Should properly distinguish the class name from its parent classes
    when each component of the declaration is on its own line."""
    code = dedent("""\
        class
        Test
        :
        public
        Other
        {
        int m_test;
        };
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [(26, 40, "Test")]


def test_comment_inside_declaration():
    """Should read the name from the declaration and not from a comment
    between the name and the curly bracket."""
    code = dedent("""\
        class Test /* : public Other */ {
        int m_test;
        };
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [(32, 46, "Test")]


def test_comment_before_base_class():
    """Should read the class name and not the base class name
    when a comment separates them."""
    code = dedent("""\
        class Test /* comment */ : public Other {
        int m_test;
        };
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [(40, 54, "Test")]


def test_interrupted_declaration():
    """Should ignore the block comment that interrupts the class declaration"""
    code = dedent("""\
        class /* ignore */ Test {
        int m_test;
        };
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [(24, 38, "Test")]


def test_template_class():
    """Should report the scope once with the name nearest to the curly bracket
    when the template parameters use the `class` keyword."""
    code = dedent("""\
        template <class T> class Test {
        int m_test;
        };
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [(30, 44, "Test")]


def test_template_class_comment_before_declaration():
    """Should report the scope once with the name nearest to the curly bracket
    when a comment separates the template parameters from the class declaration."""
    code = dedent("""\
        template <class T>
        // Comment
        class Test {
        int m_test;
        };
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [(41, 55, "Test")]


def test_keyword_inside_word():
    """Should not detect a scope where the keyword is the tail of a longer word."""
    code = dedent("""\
        subclass Test {
        int m_test;
        };
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not get_namespaces_from_scopes(code, tokens, scopes)


def test_anonymous_struct():
    """Should not declare a namespace for a struct with no name."""
    code = dedent("""\
        struct {
        int x;
        } g_anon;
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert not get_namespaces_from_scopes(code, tokens, scopes)


def test_class_name_after_declspec():
    """Should ignore prefixes like `__declspec` that are allowed in a class declaration."""
    code = dedent("""\
        class __declspec(dllexport) Test {
        int m_test;
        };
    """)
    tokens = tokenize_code_file(code)
    scopes, _ = resolve_scopes(tokens)
    assert get_namespaces_from_scopes(code, tokens, scopes) == [(33, 47, "Test")]
