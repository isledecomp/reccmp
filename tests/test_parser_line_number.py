"""Verify that the reported line number of each decomp item matches expectations."""

from textwrap import dedent  # Indenting is important here.
import pytest
from reccmp.isledecomp.parser.parser import DecompParser


@pytest.fixture(name="parser")
def fixture_parser():
    return DecompParser()


def test_function_one_liner(parser):
    """Entire function on one line"""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        void test() { hello(); world++; }
        """
        )
    )
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 2


def test_function_newline_curly(parser):
    """Allman style: curly braces always on their own line"""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        void test()
        {
            hello();
            world++;
        }
        """
        )
    )
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 6


def test_function_sameline_curly(parser):
    """K&R or 1TBS style: curly braces never on their own line"""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        void test() {
            hello();
            world++;
        }
        """
        )
    )
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 5


@pytest.mark.xfail(reason="TODO")
def test_function_newline_curly_with_code(parser):
    """Pico/Lisp style. Same syntax as AFXWIN1.INL"""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        void test()
        {   hello(); 
            world++; }
        """
        )
    )
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 4


def test_function_with_other_markers(parser):
    """Correct reporting for function with STRING and GLOBAL markers"""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        const char* test()
        {
            // GLOBAL: TEST 0x2000
            // STRING: TEST 0x3000
            const char* msg = "Hello";

            // GLOBAL: TEST 0x4000
            static int g_count = 5;

            // STRING: TEST 0x5000
            return "Test";
        }
        """
        )
    )

    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 13

    # Variable and string on same line
    assert parser.variables[0].line_number == 6
    assert parser.strings[0].line_number == 6

    # Variable by itself
    assert parser.variables[1].line_number == 9

    # String by itself
    assert parser.strings[1].line_number == 12


def test_function_allman_unexpected_function_end(parser):
    """TODO: This should probably be a syntax error instead.
    Documenting current behavior of ending the existing function gracefully
    when a second FUNCTION marker is detected."""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        void test()
        {
            hello();
            // FUNCTION: TEST 0x5555
        }
        """
        )
    )

    # Outer function ends at the line before the second FUNCTION mark
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 4


@pytest.mark.xfail(
    reason="Missed function end because closing '}' did not match tab stops of opening '{'"
)
def test_function_unequal_curly(parser):
    """Similar to previous test except that we overshoot the range of the first function."""
    parser.read(
        dedent(
            """\
            // FUNCTION: TEST 0x1234
            void test()
            {
                hello();
                }

            // FUNCTION: TEST 0x5555
            void test2()
            {
                hello();
            }
            """
        )
    )

    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 5
    assert parser.functions[1].line_number == 8
    assert parser.functions[1].end_line == 11


@pytest.mark.xfail(reason="Ends function too soon")
def test_function_no_tabbing(parser):
    """Should properly manage scope level even if curly brackets are not tabbed."""
    parser.read(
        dedent(
            """\
            // FUNCTION: TEST 0x1234
            void test()
            {
            
            if (1)
            {
                hello();
            }
            }
            """
        )
    )

    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 9


def test_synthetic(parser):
    """The SYNTHETIC marker can only be a nameref annotation."""
    parser.read(
        dedent(
            """\
        // SYNTHETIC: TEST 0x1234
        // SYNTHETIC: HELLO 0x5678
        // Test
        """
        )
    )

    # Reported line number is the comment with the name of the function
    assert parser.functions[0].line_number == 3
    assert parser.functions[0].end_line == 3


def test_string(parser):
    parser.read(
        dedent(
            """\
        // STRING: TEST 0x1234
        return "Hello";
        """
        )
    )

    # Reported line number is the one with the string
    assert parser.strings[0].line_number == 2
    # TODO: enable when end_line is added
    # assert parser.strings[0].end_line == 2


@pytest.mark.skip(
    reason="No way to properly test this without end_line attribute for strings."
)
def test_string_mutiline_concat(parser):
    """Capture multiline strings with the line continuation character (backslash)"""
    parser.read(
        dedent(
            """\
        // STRING: TEST 0x1234
        const char* test = "Hello"
        "World";
        """
        )
    )

    assert parser.strings[0].line_number == 2
    # TODO: enable when end_line is added
    # assert parser.strings[0].end_line == 3


@pytest.mark.xfail(reason="Does not register as a string with our line-based parser.")
def test_string_line_continuation(parser):
    """Capture multiline strings with the line continuation character (backslash)"""
    parser.read(
        dedent(
            """\
        // STRING: TEST 0x1234
        return "Hello \\
        World";
        """
        )
    )

    assert parser.strings[0].line_number == 2
    # TODO: enable when end_line is added
    # assert parser.strings[0].end_line == 3
