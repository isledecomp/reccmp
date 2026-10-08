import pytest
from reccmp.parser.parser import MarkerDict
from reccmp.parser.marker import (
    DecompMarker,
    MarkerType,
    match_marker,
    is_marker_exact,
    normalize_project_aliases,
)
from reccmp.parser.util import (
    is_blank_or_comment,
    get_class_name,
    get_variable_name,
    get_string_contents,
)

blank_or_comment_param = [
    (True, ""),
    (True, "\t"),
    (True, "    "),
    (False, "\tint abc=123;"),
    (True, "// OFFSET: LEGO1 0xdeadbeef"),
    (True, "   /* Block comment beginning"),
    (True, "Block comment ending */   "),
    # TODO: does clang-format have anything to say about these cases?
    (False, "x++; // Comment follows"),
    (False, "x++; /* Block comment begins"),
]


@pytest.mark.parametrize("expected, line", blank_or_comment_param)
def test_is_blank_or_comment(line: str, expected: bool):
    assert is_blank_or_comment(line) is expected


marker_samples = [
    # (can_parse: bool, exact_match: bool, line: str)
    (True, True, "// FUNCTION: LEGO1 0xdeadbeef"),
    (True, True, "// FUNCTION: ISLE 0x12345678"),
    # No trailing spaces allowed
    (True, False, "// FUNCTION: LEGO1 0xdeadbeef  "),
    # Must have exactly one space between elements
    (True, False, "//FUNCTION: ISLE 0xdeadbeef"),
    (True, False, "// FUNCTION:ISLE 0xdeadbeef"),
    (True, False, "//  FUNCTION: ISLE 0xdeadbeef"),
    (True, False, "// FUNCTION:  ISLE 0xdeadbeef"),
    (True, False, "// FUNCTION: ISLE  0xdeadbeef"),
    # Must have 0x prefix for hex number to match at all
    (False, False, "// FUNCTION: ISLE deadbeef"),
    # Offset, module name, and STUB must be uppercase
    (True, False, "// function: ISLE 0xdeadbeef"),
    (True, False, "// function: isle 0xdeadbeef"),
    # Hex string must be lowercase
    (True, False, "// FUNCTION: ISLE 0xDEADBEEF"),
    # TODO: How flexible should we be with matching the module name?
    (True, True, "// FUNCTION: OMNI 0x12345678"),
    (True, True, "// FUNCTION: LEG01 0x12345678"),
    (True, False, "// FUNCTION: hello 0x12345678"),
    # Not close enough to match
    (False, False, "// FUNCTION: ISLE0x12345678"),
    (False, False, "// FUNCTION: 0x12345678"),
    (False, False, "// LEGO1: 0x12345678"),
    # Hex string shorter than 8 characters
    (True, True, "// FUNCTION: LEGO1 0x1234"),
    # TODO: These match but shouldn't.
    # (False, False, '// FUNCTION: LEGO1 0'),
    # (False, False, '// FUNCTION: LEGO1 0x'),
    # Extra field
    (True, True, "// VTABLE: HELLO 0x1234 Extra"),
    # Extra with spaces
    (True, True, "// VTABLE: HELLO 0x1234 Whatever<SubClass *>"),
    # Extra, no space (if the first non-hex character is not in [a-f])
    (True, False, "// VTABLE: HELLO 0x1234Hello"),
    # Extra, many spaces
    (True, False, "// VTABLE: HELLO 0x1234    Hello"),
]


@pytest.mark.parametrize("match, _, line", marker_samples)
def test_marker_match(line: str, match: bool, _):
    did_match = match_marker(line) is not None
    assert did_match is match


@pytest.mark.parametrize("_, exact, line", marker_samples)
def test_marker_exact(line: str, exact: bool, _):
    assert is_marker_exact(line) is exact


def test_marker_dict_simple():
    d = MarkerDict()
    d.insert(DecompMarker(MarkerType.FUNCTION, "TEST", 0x1234))
    markers = list(d.iter())
    assert len(markers) == 1


def test_marker_dict_ofs_replace():
    d = MarkerDict()
    d.insert(DecompMarker(MarkerType.FUNCTION, "TEST", 0x1234))
    d.insert(DecompMarker(MarkerType.FUNCTION, "TEST", 0x555))
    markers = list(d.iter())
    assert len(markers) == 1
    assert markers[0].offset == 0x1234


def test_marker_dict_type_replace():
    d = MarkerDict()
    d.insert(DecompMarker(MarkerType.FUNCTION, "TEST", 0x1234))
    d.insert(DecompMarker(MarkerType.STUB, "TEST", 0x1234))
    markers = list(d.iter())
    assert len(markers) == 1
    assert markers[0].type == MarkerType.FUNCTION


class_name_match_cases = [
    ("struct MxString {", "MxString"),
    ("class MxString {", "MxString"),
    ("// class MxString", "MxString"),
    ("class MxString : public MxCore {", "MxString"),
    ("class MxPtrList<MxPresenter>", "MxPtrList<MxPresenter>"),
    # If it is possible to match the symbol MxList<LegoPathController *>::`vftable'
    # we should get the correct class name if possible. If the template type is a pointer,
    # the asterisk and class name are separated by one space.
    ("// class MxList<LegoPathController *>", "MxList<LegoPathController *>"),
    ("// class MxList<LegoPathController*>", "MxList<LegoPathController *>"),
    ("// class MxList<LegoPathController* >", "MxList<LegoPathController *>"),
    # I don't know if this would ever come up, but sure, why not?
    ("// class MxList<LegoPathController**>", "MxList<LegoPathController **>"),
    ("// class Many::Name::Spaces", "Many::Name::Spaces"),
]


@pytest.mark.parametrize("line, class_name", class_name_match_cases)
def test_get_class_name(line: str, class_name: str):
    assert get_class_name(line) == class_name


class_name_no_match_cases = [
    "MxString { ",
    "clas MxString",
    "// MxPtrList<MxPresenter>::`scalar deleting destructor'",
]


@pytest.mark.parametrize("line", class_name_no_match_cases)
def test_get_class_name_none(line: str):
    assert get_class_name(line) is None


variable_name_cases = [
    # With "g_" prefix, formerly a requirement for variables in reccmp-enabled code.
    ("char* g_test;", "g_test"),
    ("g_test;", "g_test"),
    ("void (*g_test)(int);", "g_test"),
    ("void (*g_test)(char*, int);", "g_test"),
    ("char g_test[50];", "g_test"),
    ("char g_test[50] = {1234,", "g_test"),
    ("int g_test = 500;", "g_test"),
    # no prefix
    ("char* hello;", "hello"),
    ("hello;", "hello"),
    ("void (*hello)(int);", "hello"),
    ("char hello[];", "hello"),
    ("char hello[][];", "hello"),
    ("char hello[50];", "hello"),
    ("char hello[10][50];", "hello"),
    ("char hello[50] = {1234,", "hello"),
    ("int hello = 500;", "hello"),
    ("char* gBoring_material_names[2];", "gBoring_material_names"),
    ("const FloatConstant g_floatConst4096(4096.0f);", "g_floatConst4096"),
    ("int really::really::qualified::variable hello;", "hello"),
    ("fully::qualified::type test = 5;", "test"),
]


@pytest.mark.parametrize("line,name", variable_name_cases)
def test_get_variable_name(line: str, name: str):
    assert get_variable_name(line) == name


# TODO: Drop after #509. The string will be in its own token.
string_match_cases_vestigial = [
    pytest.param('return "hello world";', "hello world", id="Return string"),
    # Only match first string if there are multiple options
    pytest.param('Method("hello", "world");', "hello", id="Multiple string tokens"),
]


string_match_cases = [
    pytest.param('""', "", id="Empty string"),
    pytest.param('"hello\\\\"', "hello\\", id="Escaped slash"),
    pytest.param(r'"\\n"', "\\n", id="Not a newline"),
    pytest.param('"hello \\"world\\""', 'hello "world"', id="Escaped double quote"),
    pytest.param('"hello\\nworld"', "hello\nworld", id="Escaped newline"),
    pytest.param('"\\N{BULLET}"', "N{BULLET}", id="Named universal character escape"),
    pytest.param('"\\a\\b\\f\\n\\r\\t\\v"', "\a\b\f\n\r\t\v", id="Escape sequences"),
    pytest.param('"\\\'\\"\\\\"', "'\"\\", id="Escaped chars"),
    pytest.param('"hello\\?"', "hello?", id="Escaped trigraph"),
    pytest.param('"\\e"', "e", id="Escaped escape char"),
    pytest.param('"\\8"', "8", id="(Invalid) Escaped digit"),
    pytest.param('"\\08"', "\0" + "8", id="NUL (one digit octal)"),
    pytest.param('"\\008"', "\0" + "8", id="NUL (two digit octal)"),
    pytest.param('"\\1"', "\x01", id="One digit octal"),
    pytest.param('"\\01"', "\x01", id="Two digit octal"),
    pytest.param('"\\007"', "\x07", id="Octal"),
    pytest.param('"\\\\007"', "\\007", id="Not an octal"),
    pytest.param('"\\1234"', "S4", id="Octal with extra digit"),
    pytest.param('"\\377"', "\xff", id="Octal 255"),
    pytest.param('"\\777"', "ǿ", id="Widechar octal"),
    pytest.param('"\\x41"', "A", id="Hex"),
    pytest.param('"\\x00041"', "A", id="Hex with leading zeroes"),
    # Python chr() accepts values up to 0x10FFFF.
    pytest.param('"\\x12345"', "\\x12345", id="Too big for wchar_t"),
    pytest.param('"\\x12345678"', "\\x12345678", id="Too big for Python"),
    # Our targeted compilers don't support these:
    pytest.param('"\\u0041"', "u0041", id="16-bit Unicode code point"),
    pytest.param('"\\U00000041"', "U00000041", id="32-bit Unicode code point"),
]


@pytest.mark.parametrize(
    "line, expected", [*string_match_cases_vestigial, *string_match_cases]
)
def test_get_string_contents(line: str, expected: str):
    string = get_string_contents(line)
    assert string is not None
    assert string.text == expected
    assert string.is_widechar is False


@pytest.mark.parametrize("line, expected", string_match_cases)
def test_get_string_contents_widechar(line: str, expected: str):
    string = get_string_contents("L" + line)
    assert string is not None
    assert string.text == expected
    assert string.is_widechar is True


def test_marker_extra_spaces():
    """The extra field can contain spaces"""
    marker = match_marker("// VTABLE: TEST 0x1234 S p a c e s")
    assert marker is not None
    assert marker.extra == "S p a c e s"

    # Trailing spaces removed
    marker = match_marker("// VTABLE: TEST 0x8888 spaces    ")
    assert marker is not None
    assert marker.extra == "spaces"

    # Trailing newline removed if present
    marker = match_marker("// VTABLE: TEST 0x5555 newline\n")
    assert marker is not None
    assert marker.extra == "newline"


def test_marker_trailing_spaces():
    """Should ignore trailing spaces. (Invalid extra field)
    Offset field not truncated, extra field set to None."""

    marker = match_marker("// VTABLE: TEST 0x1234     ")
    assert marker is not None
    assert marker.offset == 0x1234
    assert marker.extra is None


def test_marker_aliases():
    """Testing with aliases that have been normalized by normalize_project_aliases()"""
    # No alias
    marker = match_marker("// FUNC: TEST 0x1234")
    assert marker and marker.type == MarkerType.UNKNOWN

    # Alias demo
    marker = match_marker("// FUNC: TEST 0x1234", {"TEST": {"FUNC": "FUNCTION"}})
    assert marker and marker.type == MarkerType.FUNCTION

    # Aliases are scoped by target
    marker = match_marker("// FUNC: TEST 0x1234", {"HELLO": {"FUNC": "FUNCTION"}})
    assert marker and marker.type == MarkerType.UNKNOWN

    # Alias goes nowhere
    marker = match_marker("// FUNC: TEST 0x1234", {"TEST": {"FUNC": "HELLO"}})
    assert marker and marker.type == MarkerType.UNKNOWN

    # Double alias not followed
    marker = match_marker(
        "// FUNC: TEST 0x1234", {"TEST": {"FUNC": "HELLO", "HELLO": "FUNCTION"}}
    )
    assert marker and marker.type == MarkerType.UNKNOWN


def test_normalize_project_aliases():
    assert not normalize_project_aliases({})

    # Normalize target and alias names for lookup
    assert normalize_project_aliases({"test": {"func": "FUNCTION"}}) == {
        "TEST": {"FUNC": "FUNCTION"}
    }

    # Drop empty alias lists
    assert not normalize_project_aliases({"TEST": {}})

    # Drop aliases that point to nothing
    assert not normalize_project_aliases({"TEST": {"func": "FUNC"}})

    # Drop aliases that try to reassign a built-in type
    assert not normalize_project_aliases({"TEST": {"FUNCTION": "GLOBAL"}})

    # Drop duplicated alias
    assert normalize_project_aliases(
        {"TEST": {"func": "FUNCTION", "FUNC": "TEMPLATE"}}
    ) == {"TEST": {"FUNC": "FUNCTION"}}
