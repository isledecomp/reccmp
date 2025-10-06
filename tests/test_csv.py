from textwrap import dedent
import pytest
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.compare.csv import (
    csv_parse,
    CsvNoAddressError,
    CsvMultipleAddressError,
    CsvInvalidAddressError,
    CsvNoDelimiterError,
    CsvInvalidEntityTypeError,
    ReccmpCsvParserError,
)


def test_no_delimiter():
    """Must have a delimiter. Having just one column isn't very useful."""
    with pytest.raises(CsvNoDelimiterError):
        list(csv_parse("addr"))


def test_valid_addr_column():
    """The only requirement is that there is a single address column and a delimiter."""
    list(csv_parse("addr|symbol"))
    list(csv_parse("address|symbol"))


def test_no_address_column():
    """Cannot parse any rows if there is no address column."""
    with pytest.raises(CsvNoAddressError):
        list(csv_parse("symbol|test"))


def test_multiple_address_column():
    """Cannot parse any rows if there is not a single address column."""
    with pytest.raises(CsvMultipleAddressError):
        list(csv_parse("address|symbol|addr"))

    # This includes cases where the same key name is repeated
    with pytest.raises(CsvMultipleAddressError):
        list(csv_parse("addr|addr"))

    with pytest.raises(CsvMultipleAddressError):
        list(csv_parse("address|address"))


def test_value_includes_delimiter():
    """If the value contains the delimiter, we can still parse it correctly
    if the value is quoted. This is a feature of the python csv module."""
    values = list(
        csv_parse(
            dedent(
                """\
        address,symbol
        1000,"hello,world"
    """
            )
        )
    )

    assert values == [(0x1000, {"symbol": "hello,world"})]


def test_ignore_columns():
    """We only parse certain columns that correspond to attribute names in the database."""
    values = list(
        csv_parse(
            dedent(
                """\
        address|symbol|test
        1000|hello|123
    """
            )
        )
    )

    assert values == [(0x1000, {"symbol": "hello"})]


def test_address_not_hex():
    """Raise an exception if we cannot parse the address on one of the rows."""
    with pytest.raises(CsvInvalidAddressError):
        list(
            csv_parse(
                dedent(
                    """\
            addr|symbol
            wrong|test
        """
                )
            )
        )


def test_too_many_columns():
    """Should ignore extra values in a row."""
    values = list(
        csv_parse(
            dedent(
                """\
        addr|symbol
        1000|hello|world
    """
            )
        )
    )

    assert values == [(0x1000, {"symbol": "hello"})]


def test_blank_column_header():
    """Should ignore a blank column header and its value"""
    values = list(
        csv_parse(
            dedent(
                """\
        addr|symbol||type
        1000|hello|world|function
    """
            )
        )
    )

    assert values == [(0x1000, {"symbol": "hello", "type": EntityType.FUNCTION})]


def test_ignore_blank_lines():
    """Parsing should ignore blank lines.
    n.b. make sure the triple quote string and dedent() remove leading spaces."""
    values = list(
        csv_parse(
            dedent(
                """\

                addr|symbol

                1000|test

                2000|test


                3000|test
            """
            )
        )
    )

    assert values == [
        (0x1000, {"symbol": "test"}),
        (0x2000, {"symbol": "test"}),
        (0x3000, {"symbol": "test"}),
    ]


def test_ignore_comments():
    """We ignore any line starting with // or #."""
    values = list(
        csv_parse(
            dedent(
                """\
                # Test CSV file
                addr|symbol
                # 1000|test
                2000|test
                // 3000|test
            """
            )
        )
    )

    assert values == [(0x2000, {"symbol": "test"})]


def test_tab_delimiter():
    """We support tab as an option for delimiter. (It is not covered in the other tests.)"""
    values = list(
        csv_parse(
            dedent(
                """\
                addr\tsymbol
                1000\ttest
                2000\ttest
                3000\ttest
            """
            )
        )
    )

    assert values == [
        (0x1000, {"symbol": "test"}),
        (0x2000, {"symbol": "test"}),
        (0x3000, {"symbol": "test"}),
    ]


def test_emulate_file_reads():
    """The tests thus far have used a string, which is split on the newline.
    This means each line is *missing* the newline. Make sure we can still parse if
    we are reading line-by-line, as from a file."""

    # Mix of comments and blank lines
    file = iter(
        ["# Comment\n", "\n", "addr|symbol\n", "\n", "1000|test\n", "\n", "2000|test\n"]
    )
    values = list(csv_parse(file))

    assert values == [
        (0x1000, {"symbol": "test"}),
        (0x2000, {"symbol": "test"}),
    ]


def test_address_not_first():
    """Since the address is the unique id for the annotation, it will probably appear first in most cases.
    However, this is not required."""

    values = list(
        csv_parse(
            dedent(
                """\
                symbol|name|addr
                test|hello|1000
                test|world|2000
            """
            )
        )
    )

    addrs = [addr for addr, _ in values]
    assert addrs == [0x1000, 0x2000]


def test_address_repeated():
    """The address can appear more than once and we will parse it correctly.
    It's up to the caller to decide how to handle this."""

    values = list(
        csv_parse(
            dedent(
                """\
                addr|name
                1000|hello
                1000|world
            """
            )
        )
    )

    assert values == [(0x1000, {"name": "hello"}), (0x1000, {"name": "world"})]


def test_type():
    """Should convert the type column to the EntityType enum."""

    # Fail if the user's string doesn't resolve to one of our types.
    with pytest.raises(CsvInvalidEntityTypeError):
        list(csv_parse("address|type\n1234|hello"))

    values = list(csv_parse("address|type\n1234|function\n2345|global"))

    assert values == [
        (0x1234, {"type": EntityType.FUNCTION}),
        (0x2345, {"type": EntityType.DATA}),
    ]

    # Should allow mixed case.
    values = list(csv_parse("address|type\n1234|FUNCTION"))

    assert values == [
        (0x1234, {"type": EntityType.FUNCTION}),
    ]


def test_header_case():
    """Should allow mixed/upper/lower case for header line."""
    values = list(
        csv_parse(
            dedent(
                """\
                ADDR|NAME
                1000|hello
                1000|world
            """
            )
        )
    )

    assert values == [(0x1000, {"name": "hello"}), (0x1000, {"name": "world"})]


def test_ignore_empty_values():
    """If a field has no value, we should not put anything in the output dict."""
    values = list(
        csv_parse(
            dedent(
                """\
            address|type|name|size
            1234||hello|
            1234|||5
            1234|function||
            1234|||
            """
            )
        )
    )

    assert values == [
        (0x1234, {"name": "hello"}),
        (0x1234, {"size": 5}),
        (0x1234, {"type": EntityType.FUNCTION}),
        # We should still return an empty dict if the row is empty.
        # The caller can discard this if they want.
        (0x1234, {}),
    ]


def test_type_function_aliases():
    """All these options for "type" resolve to EntityType.FUNCTION"""
    values = list(
        csv_parse(
            dedent(
                """\
            address|type
            1234|function
            1234|library
            1234|stub
            1234|template
            1234|synthetic
            """
            )
        )
    )

    assert all(row["type"] == EntityType.FUNCTION for _, row in values)


def test_type_field_conversion():
    """The string in the "type" field is converted to the EntityType enum.
    This allows for some flexibility in the supported values."""
    values = list(
        csv_parse(
            dedent(
                """\
            address|type
            1234|function
            1234|FUNCTION
            1234|FuNcTiOn
            1234|  function
            1234|function  
            1234|"  function  "
            """
            )
        )
    )

    assert all(row["type"] == EntityType.FUNCTION for _, row in values)


def test_function_type_side_effects():
    """Should set additional fields if the CSV type field is LIBRARY or STUB.
    Both are aliases for FUNCTION, so use this enum value in the final "type" attribute.
    """
    values = list(
        csv_parse(
            dedent(
                """\
            address|type
            1234|function
            1234|library
            1234|stub
            """
            )
        )
    )

    assert values == [
        (0x1234, {"type": EntityType.FUNCTION}),
        (0x1234, {"type": EntityType.FUNCTION, "library": True}),
        (0x1234, {"type": EntityType.FUNCTION, "stub": True}),
    ]


def test_continuable():
    """Make sure we can continue parsing after handling a non-fatal error."""
    text = dedent(
        """\
        address|type
        5555|libary
        1234|function
        zzzz|function
        4321|template
        """
    )

    # Should throw for "libary"
    with pytest.raises(ReccmpCsvParserError):
        list(csv_parse(text))

    # Parse the same text but catch the exception
    values = []
    reader = csv_parse(text)
    while True:
        try:
            values.append(next(reader))
        except StopIteration:
            break
        except ReccmpCsvParserError:
            continue

    # Should exclude the two failed values and return the ones we can parse.
    assert values == [
        (0x1234, {"type": EntityType.FUNCTION}),
        (0x4321, {"type": EntityType.FUNCTION}),
    ]


def test_exception_details():
    """Should capture the original line number (before removing blank lines)
    and the value that led to the exception and report both."""
    text = dedent(
        """\
        address|type

        5555|libary
        1234|function

        zzzz|function
        4321|template
        """
    )

    reader = csv_parse(text)

    # 5555|libary
    with pytest.raises(CsvInvalidEntityTypeError) as excinfo:
        next(reader)
        assert excinfo.value.illegal_value == "libary"
        assert excinfo.value.line_number == 3

    # 1234|function
    assert next(reader) == (0x1234, {"type": EntityType.FUNCTION})

    # zzzz|function
    with pytest.raises(CsvInvalidAddressError) as excinfo:
        next(reader)
        assert excinfo.value.illegal_value == "zzzz"
        assert excinfo.value.line_number == 6

    # 4321|template
    assert next(reader) == (0x4321, {"type": EntityType.FUNCTION})

    # Done
    with pytest.raises(StopIteration):
        next(reader)


def test_docs_example_basic():
    """Just make sure we can parse it"""
    text = dedent(
        """\
        address|name|size
        1008b400|_atol|164
        1008b4b0|_atoi|14
        1008b4c0|_strtok|216
        1008b5a0|_sprintf|103
        1008b608|__ftol|39"""
    )
    assert (0x1008B400, {"name": "_atol", "size": 164}) in list(csv_parse(text))


def test_docs_example_null_field():
    """0x10001070 has null type"""
    text = dedent(
        """\
        address|type|size
        0x10001000|function|92
        0x10001070||25
        0x10001090|function|10"""
    )
    assert (0x10001070, {"size": 25}) in list(csv_parse(text))


def test_docs_example_quoted_field():
    """Can parse double-quote-wrapped field that contains delimiter"""
    text = dedent(
        """\
        addr,name
        101310a0,\"set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >\""""
    )
    assert (
        0x101310A0,
        {
            "name": "set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >"
        },
    ) in list(csv_parse(text))


def test_docs_example_comments_and_blanks():
    """Should ignore comment lines and blank lines"""
    text = dedent(
        """\
        addr,type

        # Months of the year
        100db57c,string
        100db588,string
        100db594,string

        # Days of the week
        100db614,string
        100db620,string
        100db628,string"""
    )
    assert (0x100DB614, {"type": EntityType.STRING}) in list(csv_parse(text))


def test_ignore_skip():
    """Should ignore 'skip' field until we reinstate it."""
    text = "addr|skip\n1234|1"
    assert (0x1234, {}) in list(csv_parse(text))
