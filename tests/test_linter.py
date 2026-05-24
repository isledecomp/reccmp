from pathlib import PurePath
from reccmp.parser import DecompParser, ReccmpParserResult
from reccmp.parser.error import AlertCode
from reccmp.parser.linter import (
    check_byname_allowed,
    check_function_order,
    check_offset_uniqueness,
    check_string_text,
)


def create_parser_result(code: str, path: PurePath) -> ReccmpParserResult:
    """Since #416, the linter is a higher-level interpreter of parser results instead of a wrapper.
    This converts the text/path into results to try to minimize changes to the existing tests.
    """
    parser = DecompParser()
    parser.reset_and_set_filename(path)
    parser.read(code)
    parser.finish()
    return parser.to_result()


def test_order_in_order():
    """Functions from the same module are in order. No problems here."""
    code = """\
        // FUNCTION: TEST 0x1000
        void function1() {}
        // FUNCTION: TEST 0x2000
        void function2() {}
        // FUNCTION: TEST 0x3000
        void function3() {}
        """

    result = create_parser_result(code, PurePath("test.cpp"))
    assert not check_function_order(result)


def test_order_out_of_order():
    """Detect functions that are out of order."""
    code = """\
        // FUNCTION: TEST 0x1000
        void function1() {}
        // FUNCTION: TEST 0x3000
        void function3() {}
        // FUNCTION: TEST 0x2000
        void function2() {}
        """

    path = PurePath("test.cpp")
    result = create_parser_result(code, path)
    alerts = check_function_order(result)

    assert len(alerts) == 1
    assert alerts[0].code == AlertCode.FUNCTION_OUT_OF_ORDER
    # N.B. Line number given is the start of the function, not the marker
    assert alerts[0].line_number == 6
    # Identifying details of the alert's origin are now embedded.
    assert alerts[0].target == "TEST"
    assert alerts[0].path == PurePath("test.cpp")


def test_order_ignore_lookup_by_name():
    """Should ignore lookup-by-name markers when checking order."""
    code = """\
        // FUNCTION: TEST 0x1000
        void function1() {}
        // FUNCTION: TEST 0x3000
        // MyClass::MyMethod
        // FUNCTION: TEST 0x2000
        void function2() {}
        """

    result = create_parser_result(code, PurePath("test.h"))
    assert not check_function_order(result)


def test_order_reports_all_modules():
    """Any ordering problems from any module are reported. The caller should filter for display."""
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

    result = create_parser_result(code, PurePath("test.cpp"))
    alerts = check_function_order(result)

    # ALPHA markers are out of order.
    assert {alert.target for alert in alerts} == {"ALPHA"}


def test_byname_headers_only():
    """Markers referenced by name belong in header files only."""
    code = """\
        // FUNCTION: TEST 0x1000
        // MyClass::~MyClass
        """

    result_cpp = create_parser_result(code, PurePath("test.cpp"))
    result_h = create_parser_result(code, PurePath("test.h"))

    assert not check_byname_allowed(result_h)

    alerts = check_byname_allowed(result_cpp)
    assert alerts[0].code == AlertCode.BYNAME_FUNCTION_IN_CPP


def test_duplicate_offsets_module_scope():
    """All duplicate offsets from all modules are reported. The caller should filter for display."""
    code = """\
        // FUNCTION: TEST 0x1000
        // FUNCTION: HELLO 0x1000
        // MyClass::~MyClass
        """

    result = create_parser_result(code, PurePath("test.h"))

    # Should not fail for duplicate offset 0x1000 because the modules are unique.
    assert not check_offset_uniqueness([result])

    # Simulate a failure by reading the same file twice.
    alerts = check_offset_uniqueness([result, result])

    # Duplicate addresses from both modules are reported.
    assert len(alerts) == 2
    assert {alert.target for alert in alerts} == {"HELLO", "TEST"}


def test_duplicate_strings():
    """Duplicate string markers are okay if the string value is the same."""
    string_lines = """\
        // STRING: TEST 0x1000
        return "hello world";
        """

    string_hello = create_parser_result(string_lines, PurePath("test.h"))

    assert not check_string_text([string_hello])
    assert not check_string_text([string_hello, string_hello])
    assert not check_offset_uniqueness([string_hello])
    assert not check_offset_uniqueness([string_hello, string_hello])

    different_string = """\
        // STRING: TEST 0x1000
        return "hi there";
        """

    # Same address but the string is different
    string_hi = create_parser_result(different_string, PurePath("greeting.h"))
    alerts = check_string_text([string_hello, string_hi])
    assert len(alerts) == 1
    assert alerts[0].code == AlertCode.WRONG_STRING

    # Strings are skipped by the uniqueness check.
    assert not check_offset_uniqueness([string_hello, string_hi])


def test_ignore_folded_duplicate():
    """Do not alert to folded functions that reuse an address."""
    folded_lines = """\
    // FUNCTION: TEST 0x1000 FOLDED
    void folded() {}

    // FUNCTION: TEST 0x1000 FOLDED
    void first() {}
    """

    result = create_parser_result(folded_lines, PurePath("test.cpp"))
    assert not check_offset_uniqueness([result, result])


def test_ignore_folded_and_regular_duplicate():
    """Should alert when folded and non-folded functions reuse an address."""
    folded_lines = """\
    // FUNCTION: TEST 0x1000 FOLDED
    void folded() {}

    // FUNCTION: TEST 0x1000
    void first() {}
    """

    result = create_parser_result(folded_lines, PurePath("test.cpp"))
    alerts = check_offset_uniqueness([result, result])
    assert alerts[0].code == AlertCode.DUPLICATE_OFFSET


def test_ignore_folded_order():
    """Skip folded functions and do not check their order."""
    folded_lines = """\
    // FUNCTION: TEST 0x2000 FOLDED
    void folded() {}

    // FUNCTION: TEST 0x1000
    void first() {}
    """

    result = create_parser_result(folded_lines, PurePath("test.cpp"))
    assert not check_function_order(result)


def test_folded_with_real_order_error():
    """Folded functions should not prevent us from reporting
    that regular functions are out of order."""
    folded_lines = """\
    // FUNCTION: TEST 0x3000
    void third() {}

    // FUNCTION: TEST 0x2000 FOLDED
    void folded() {}

    // FUNCTION: TEST 0x1000
    void first() {}
    """

    result = create_parser_result(folded_lines, PurePath("test.cpp"))
    alerts = check_function_order(result)
    assert alerts
