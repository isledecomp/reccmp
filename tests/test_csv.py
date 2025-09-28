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


def test_should_output_bool():
    """Return bool for certain column values, with some flexibility around possible text values."""

    # Using "skip" as an example of a columm where we convert from str to bool:
    values = list(
        csv_parse(
            dedent(
                """\
                addr|skip
                1000|1
                2000|yes
                3000|no
                4000|FALSE
                5000|0
            """
            )
        )
    )

    # To make the following code cleaner
    skip_map = {addr: row["skip"] for addr, row in values}

    # Any text is considered true...
    assert skip_map[0x1000] is True
    assert skip_map[0x2000] is True

    # except the values for these columns
    assert skip_map[0x3000] is False
    assert skip_map[0x4000] is False
    assert skip_map[0x5000] is False


def test_bool_with_whitespace():
    """Test even greater flexibility for fields that resolve to bool."""
    values = list(
        csv_parse(
            dedent(
                """\
                addr|skip
                1000|  false
                1000|false  
                1000|" false "
            """
            )
        )
    )

    assert (row["skip"] is False for _, row in values)


def test_bool_with_all_whitespace():
    """All whitespace resolves to no-value for a bool column."""
    values = list(csv_parse("addr|skip\n1000|   "))
    assert values == [(0x1000, {})]


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
                symbol|skip|addr
                test|1|1000
                test|0|2000
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
                addr|skip
                1000|1
                1000|0
            """
            )
        )
    )

    assert values == [(0x1000, {"skip": True}), (0x1000, {"skip": False})]


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
                ADDR|SKIP
                1000|1
                1000|0
            """
            )
        )
    )

    assert values == [(0x1000, {"skip": True}), (0x1000, {"skip": False})]


def test_ignore_empty_values():
    """If a field has no value, we should not put anything in the output dict."""
    values = list(
        csv_parse(
            dedent(
                """\
            address|type|name|size|skip
            1234||hello||
            1234|||5|
            1234|function|||
            1234||||
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

    count = 0
    reader = csv_parse(text)
    while True:
        try:
            next(reader)
        except StopIteration:
            break
        except CsvInvalidAddressError as ex:
            assert ex.illegal_value == "zzzz"
            assert ex.line_number == 6
            count += 1
            continue
        except CsvInvalidEntityTypeError as ex:
            assert ex.illegal_value == "libary"
            assert ex.line_number == 3
            count += 1
            continue

    assert count == 2
