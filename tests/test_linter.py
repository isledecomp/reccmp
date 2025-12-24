from pathlib import PurePath
import pytest
from reccmp.isledecomp.parser import DecompLinter
from reccmp.isledecomp.parser.error import ParserError


@pytest.fixture(name="linter")
def fixture_linter():
    return DecompLinter()


def test_order_in_order(linter: DecompLinter):
    """Functions from the same module are in order. No problems here."""
    code = """\
        // FUNCTION: TEST 0x1000
        void function1() {}
        // FUNCTION: TEST 0x2000
        void function2() {}
        // FUNCTION: TEST 0x3000
        void function3() {}
        """
    assert linter.read(code, PurePath("test.cpp"), "TEST") is True


def test_order_out_of_order(linter: DecompLinter):
    """Detect functions that are out of order."""
    code = """\
        // FUNCTION: TEST 0x1000
        void function1() {}
        // FUNCTION: TEST 0x3000
        void function3() {}
        // FUNCTION: TEST 0x2000
        void function2() {}
        """
    assert linter.read(code, PurePath("test.cpp"), "TEST") is False
    assert len(linter.alerts) == 1

    assert linter.alerts[0].code == ParserError.FUNCTION_OUT_OF_ORDER
    # N.B. Line number given is the start of the function, not the marker
    assert linter.alerts[0].line_number == 6


def test_order_ignore_lookup_by_name(linter: DecompLinter):
    """Should ignore lookup-by-name markers when checking order."""
    code = """\
        // FUNCTION: TEST 0x1000
        void function1() {}
        // FUNCTION: TEST 0x3000
        // MyClass::MyMethod
        // FUNCTION: TEST 0x2000
        void function2() {}
        """

    assert linter.read(code, PurePath("test.h"), "TEST") is True


def test_order_module_isolation(linter: DecompLinter):
    """Should check the order of markers from a single module only."""
    code = """\
        // FUNCTION: ALPHA 0x0003
        // FUNCTION: TEST 0x1000
        void function1() {}
        // FUNCTION: ALPHA 0x0002
        // FUNCTION: TEST 0x2000
        void function2() {}
        // FUNCTION: ALPHA 0x0001
        // FUNCTION: TEST 0x3000
        void function3() {}
        """

    assert linter.read(code, PurePath("test.cpp"), "TEST") is True
    linter.full_reset()
    assert linter.read(code, PurePath("test.cpp"), "ALPHA") is False


def test_byname_headers_only(linter: DecompLinter):
    """Markers that ar referenced by name with cvdump belong in header files only."""
    code = """\
        // FUNCTION: TEST 0x1000
        // MyClass::~MyClass
        """

    assert linter.read(code, PurePath("test.h"), "TEST") is True
    linter.full_reset()
    assert linter.read(code, PurePath("test.cpp"), "TEST") is False
    assert linter.alerts[0].code == ParserError.BYNAME_FUNCTION_IN_CPP


def test_duplicate_offsets_module_scope(linter: DecompLinter):
    """The linter will retain module/offset pairs found until we do a full reset."""
    code = """\
        // FUNCTION: TEST 0x1000
        // FUNCTION: HELLO 0x1000
        // MyClass::~MyClass
        """

    # Should not fail for duplicate offset 0x1000 because the modules are unique.
    assert linter.read(code, PurePath("test.h"), "TEST") is True

    # Simulate a failure by reading the same file twice.
    assert linter.read(code, PurePath("test.h"), "TEST") is False

    # Only one error because we are focused on the TEST module
    assert len(linter.alerts) == 1
    assert all(a.code == ParserError.DUPLICATE_OFFSET for a in linter.alerts)

    # Partial reset (i.e. starting a new file) will retain the list of seen offsets.
    assert linter.read(code, PurePath("test.h"), "TEST") is False

    # Full reset will forget seen offsets.
    linter.full_reset()
    assert linter.read(code, PurePath("test.h"), "TEST") is True


def test_duplicate_offsets_all(linter: DecompLinter):
    """If we do not specify a module, check everything"""
    code = """\
        // FUNCTION: TEST 0x1000
        // FUNCTION: HELLO 0x1000
        // MyClass::~MyClass
        """

    # Simulate a failure by reading the same file twice.
    assert linter.read(code, PurePath("test.h"), None) is True
    assert linter.read(code, PurePath("test.h"), None) is False
    assert all(a.code == ParserError.DUPLICATE_OFFSET for a in linter.alerts)


def test_duplicate_offsets_isolation(linter: DecompLinter):
    """Ignore problems in another module unless we ask for them."""
    code = """\
        // FUNCTION: TEST 0x1000
        // FUNCTION: HELLO 0x1000
        // MyClass::MyClass
        // FUNCTION: TEST 0x1000
        // FUNCTION: HELLO 0x2000
        // MyClass::~MyClass
        """

    # No module = check everything
    assert linter.read(code, PurePath("test.h"), None) is False

    linter.full_reset()
    assert linter.read(code, PurePath("test.h"), "TEST") is False

    linter.full_reset()
    assert linter.read(code, PurePath("test.h"), "HELLO") is True


def test_duplicate_strings(linter: DecompLinter):
    """Duplicate string markers are okay if the string value is the same."""
    string_lines = """\
        // STRING: TEST 0x1000
        return "hello world";
        """

    # No problem to use this marker twice.
    assert linter.read(string_lines, PurePath("test.h"), "TEST") is True
    assert linter.read(string_lines, PurePath("test.h"), "TEST") is True

    different_string = """\
        // STRING: TEST 0x1000
        return "hi there";
        """

    # Same address but the string is different
    assert linter.read(different_string, PurePath("greeting.h"), "TEST") is False
    assert len(linter.alerts) == 1
    assert linter.alerts[0].code == ParserError.WRONG_STRING

    same_addr_reused = """\
        // GLOBAL:TEXT 0x1000
        int g_test = 123;
        """

    # This will fail like any other offset reuse.
    assert linter.read(same_addr_reused, PurePath("other.h"), "TEST") is False
