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
    values = [
        *csv_parse(
            dedent(
                """\
        address,symbol
        1000,"hello,world"
    """
            )
        )
    ]

    assert values == [(0x1000, {"symbol": "hello,world"})]


def test_ignore_columns():
    """We only parse certain columns that correspond to attribute names in the database."""
    values = [
        *csv_parse(
            dedent(
                """\
        address|symbol|test
        1000|hello|123
    """
            )
        )
    ]

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
    values = [
        *csv_parse(
            dedent(
                """\
        addr|symbol
        1000|hello|world
    """
            )
        )
    ]

    assert values == [(0x1000, {"symbol": "hello"})]


def test_should_output_bool():
    """Return bool for certain column values, with some flexibility around possible text values."""

    # Using "skip" as an example of a columm where we convert from str to bool:
    values = [
        *csv_parse(
            dedent(
                """\
                addr|skip
                1000|1
                2000|yes
                3000|no
                4000|FALSE
                5000|0
                6000|
            """
            )
        )
    ]

    # To make the following code cleaner
    skip_map = {addr: row["skip"] for addr, row in values}

    # Any text is considered true...
    assert skip_map[0x1000] is True
    assert skip_map[0x2000] is True

    # except the values for these columns
    assert skip_map[0x3000] is False
    assert skip_map[0x4000] is False
    assert skip_map[0x5000] is False

    # Empty string considered false
    assert skip_map[0x6000] is False


def test_ignore_blank_lines():
    """Parsing should ignore blank lines.
    n.b. make sure the triple quote string and dedent() remove leading spaces."""
    values = [
        *csv_parse(
            dedent(
                """\

                addr|symbol

                1000|test

                2000|test


                3000|test
            """
            )
        )
    ]

    assert values == [
        (0x1000, {"symbol": "test"}),
        (0x2000, {"symbol": "test"}),
        (0x3000, {"symbol": "test"}),
    ]


def test_ignore_comments():
    """We ignore any line starting with // or #."""
    values = [
        *csv_parse(
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
    ]

    assert values == [(0x2000, {"symbol": "test"})]


def test_tab_delimiter():
    """We support tab as an option for delimiter. (It is not covered in the other tests.)"""
    values = [
        *csv_parse(
            dedent(
                """\
                addr\tsymbol
                1000\ttest
                2000\ttest
                3000\ttest
            """
            )
        )
    ]

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
    values = [*csv_parse(file)]

    assert values == [
        (0x1000, {"symbol": "test"}),
        (0x2000, {"symbol": "test"}),
    ]


def test_address_not_first():
    """Since the address is the unique id for the annotation, it will probably appear first in most cases.
    However, this is not required."""

    values = [
        *csv_parse(
            dedent(
                """\
                symbol|skip|addr
                test|1|1000
                test|0|2000
            """
            )
        )
    ]

    addrs = [addr for addr, _ in values]
    assert addrs == [0x1000, 0x2000]


def test_address_repeated():
    """The address can appear more than once and we will parse it correctly.
    It's up to the caller to decide how to handle this."""

    values = [
        *csv_parse(
            dedent(
                """\
                addr|skip
                1000|1
                1000|0
            """
            )
        )
    ]

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
    values = [
        *csv_parse(
            dedent(
                """\
                ADDR|SKIP
                1000|1
                1000|0
            """
            )
        )
    ]

    assert values == [(0x1000, {"skip": True}), (0x1000, {"skip": False})]
