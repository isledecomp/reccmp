"""Verify that the reported line number of each decomp item matches expectations."""

from textwrap import dedent  # Indenting is important here.
import pytest
from reccmp.decomp.parser.parser import DecompParser


@pytest.fixture(name="parser")
def fixture_parser():
    return DecompParser()


# For each of these variations on function indenting style,
# we should report the function start and end lines accurately
# and without reporting any warnings or errors.


def test_function_indent_one_line(parser: DecompParser):
    """Declaration and brackets are all on the same line."""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        void test() { }
        """
        )
    )
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 2


def test_function_indent_allman(parser: DecompParser):
    """Declaration and brackets are each on their own line."""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        void test()
        {
        }
        """
        )
    )
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 4


def test_function_indent_allman_declaration_indented(parser: DecompParser):
    """Declaration has different tab stop but both brackets match."""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
          void test()
        {
        }
        """
        )
    )
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 4


@pytest.mark.xfail(reason="Function range detection depends on whitespace.")
def test_function_indent_allman_first_bracket_indented(parser: DecompParser):
    """First bracket indented. Second is not indented."""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        void test()
          {
        }
        """
        )
    )
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 4


@pytest.mark.xfail(reason="Function range detection depends on whitespace.")
def test_function_indent_allman_second_bracket_indented(parser: DecompParser):
    """First bracket not indented. Second is indented."""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        void test()
        {
          }
        """
        )
    )
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 4


def test_function_indent_knr(parser: DecompParser):
    """Declaration and opening bracket on same line. Closing bracket on its own line."""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        void test() {
        }
        """
        )
    )
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 3


def test_function_indent_knr_declaration_indented(parser: DecompParser):
    """Declaration and first bracket indented. Second bracket not indented."""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
          void test() {
        }
        """
        )
    )
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 3


@pytest.mark.xfail(reason="Function range detection depends on whitespace.")
def test_function_indent_knr_second_bracket_indented(parser: DecompParser):
    """Declaration and first bracket not indented. Second bracket indented."""
    parser.read(
        dedent(
            """\
        // FUNCTION: TEST 0x1234
        void indented() {
          }
        """
        )
    )
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 3


@pytest.mark.xfail(reason="Function range detection depends on whitespace.")
def test_function_indent_lisp(parser: DecompParser):
    """Brackets are on different lines but on the same line as code.
    Same syntax as AFXWIN1.INL"""
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
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 4


@pytest.mark.xfail(reason="Ends function too soon")
def test_function_indent_no_indents(parser: DecompParser):
    """Function contains additional brackets and none are indented."""
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
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 9


def test_function_indent_preprocessor_with_brackets(parser: DecompParser):
    """Two preprocessor options both with a bracket."""
    parser.read(
        dedent(
            """\
            // FUNCTION: TEST 0x1234
            void test()
            {
            #if 1
                do {
            #else
                do {
            #endif
                } while (0);
            }
            """
        )
    )
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 10


def test_function_with_other_markers(parser: DecompParser):
    """Should report the correct line numbers for the function and its component variables and strings."""
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


@pytest.mark.xfail(reason="Function range detection depends on whitespace.")
def test_function_indent_multiple_functions(parser: DecompParser):
    """Brackets with different tab stobs should not raise MISSED_END_OF_FUNCTION when we read a second function."""
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
    # Should not report unexpected end of function.
    assert len(parser.alerts) == 0
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 5
    assert parser.functions[1].line_number == 8
    assert parser.functions[1].end_line == 11


def test_nameref(parser: DecompParser):
    """The line number given for a lookup-by-name annotation is the line where the name appears."""
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


def test_string(parser: DecompParser):
    """The reported line number for a STRING annotation is the line with the string."""
    parser.read(
        dedent(
            """\
        // STRING: TEST 0x1234
        return "Hello";
        """
        )
    )

    assert parser.strings[0].line_number == 2
    # TODO: enable when end_line is added
    # assert parser.strings[0].end_line == 2


@pytest.mark.skip(reason="String annotations do not set the end_line attribute.")
def test_string_mutiline_concat(parser: DecompParser):
    """Capture multiline strings WITHOUT the line continuation character (backslash)"""
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
def test_string_line_continuation(parser: DecompParser):
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
