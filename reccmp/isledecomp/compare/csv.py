"""Parsing files in csv format.
The python csv.DictReader class does the heavy lifting.
We begin with a pre-processing step that removes blank lines or "comment" lines that begin with # or //.
The delimiter is decided based on the first line (following pre-processing). Options are: pipe, comma, tab
"""

import csv
from csv import Error as PythonCsvError
from typing import Iterable, Iterator
from typing_extensions import NotRequired, TypedDict
from reccmp.isledecomp.types import EntityType


# Fatal errors:


class ReccmpCsvFatalParserError(Exception):
    """Cannot return even a single row from this document."""


class CsvNoAddressError(ReccmpCsvFatalParserError):
    """This file does not have an address attribute."""


class CsvMultipleAddressError(ReccmpCsvFatalParserError):
    """This file has more than one address attribute
    (and it's not clear which one we should use)."""


class CsvNoDelimiterError(ReccmpCsvFatalParserError):
    """No obvious delimiter on the first line."""


# Non-fatal errors:


class ReccmpCsvParserError(Exception):
    """Cannot parse the row in question."""

    illegal_value: str
    line_number: int

    def __init__(self, value: str):
        self.illegal_value = value
        self.line_number = -1

    def __str__(self) -> str:
        return f"{self.__class__.__name__}: line {self.line_number}, '{self.illegal_value}'"


class CsvInvalidAddressError(ReccmpCsvParserError):
    """The address value is not a valid hex number."""


class CsvInvalidEntityTypeError(ReccmpCsvParserError):
    """The entity type string did not match any of our allowed values."""


CsvValueOptions = int | str | bool | EntityType


class CsvValuesType(TypedDict):
    type: NotRequired[EntityType]
    name: NotRequired[str]
    size: NotRequired[int]
    skip: NotRequired[bool]
    symbol: NotRequired[str]

    # Set implicitly via type for now
    stub: NotRequired[bool]
    library: NotRequired[bool]


def _boolify(text: str) -> bool:
    """str to bool conversion. If the string is not in the exclusion list, resolve to True."""
    return text.strip().lower() not in ("false", "off", "no", "0", "")


_entity_type_map = {
    # Aliases for FUNCTION used in code annotations:
    "function": EntityType.FUNCTION,
    "template": EntityType.FUNCTION,
    "synthetic": EntityType.FUNCTION,
    "library": EntityType.FUNCTION,
    "stub": EntityType.FUNCTION,
    # Other types:
    "global": EntityType.DATA,
    "string": EntityType.STRING,
    "float": EntityType.FLOAT,
    "vtable": EntityType.VTABLE,
}


def _typeify(name: str) -> EntityType:
    """Text to EntityType enum conversion"""
    try:
        return _entity_type_map[name]
    except KeyError as ex:
        raise CsvInvalidEntityTypeError(name) from ex


def _csv_preprocess(lines: Iterable[str]) -> Iterator[tuple[int, str]]:
    """Remove comments and blank lines so we have an easier time parsing the CSV.
    Include the original line number so that we can reference it in error messages."""
    for i, line in enumerate(lines, start=1):
        strip = line.strip()
        # Skip comment lines
        if strip.startswith("#") or strip.startswith("//"):
            continue

        # Skip blank lines.
        if strip == "":
            continue

        yield (i, line)


def _convert_attrs(values: Iterable[tuple[str, str]]) -> CsvValuesType:
    """Both a filter and a conversion step for the row values.
    For the incoming iterable of key/value pairs, only output the ones we want set
    in the reccmp database. Some keys have their value converted to a different type."""
    output: CsvValuesType = {}

    for key, value in values:
        # Skip any value without a column header. (None or empty string)
        if not key:
            continue

        # Skip any blank value (including whitespace).
        if not value.strip():
            continue

        if key == "symbol":
            output["symbol"] = value

        if key == "name":
            output["name"] = value

        if key == "size":
            output["size"] = int(value)

        if key == "type":
            type_name = value.strip().lower()
            output["type"] = _typeify(type_name)

            # To imitate the handling for code annotations, set these
            # extra attribtues based on the FUNCTION alias that was used.
            if type_name == "stub":
                output["stub"] = True

            # Support --no-lib option (#206)
            if type_name == "library":
                output["library"] = True

        if key in ("report_skip", "report.skip", "skip"):
            output["skip"] = _boolify(value)

    return output


def _csv_convert(addr_key: str, row: dict[str, str]) -> tuple[int, CsvValuesType]:
    """Pull out the address from the CSV row and convert the remaining key/value pairs."""
    try:
        # Addr is always a hex number
        addr_value = row[addr_key]
        addr = int(addr_value, 16)
    except ValueError as ex:
        raise CsvInvalidAddressError(addr_value) from ex

    return (addr, _convert_attrs(row.items()))


class ReccmpCsvReader:
    addr_key: str
    reader: csv.DictReader
    line_number_map: dict[int, int]

    def __init__(self, lines: str | Iterable[str]) -> None:
        """Reads each line from the csv file and outputs each address and its key/value pairs."""
        if isinstance(lines, str):
            lines = lines.split("\n")

        # Split list of (line_number, line) into (list of line_numbers, list of lines)
        select_line_numbers, select_lines = zip(*_csv_preprocess(lines))
        self.line_number_map = dict(enumerate(select_line_numbers, start=1))

        # We expect lower-case keys. Convert the first line so the dicts returned by the csv reader will match.
        # zip returns a tuple so we can't modify the first value in-place.
        preprocessed = (select_lines[0].lower(), *select_lines[1:])

        try:
            # Use the first line (only) to find the delimiter
            dialect = csv.Sniffer().sniff(preprocessed[0], delimiters="|,\t")
        except PythonCsvError as ex:
            raise CsvNoDelimiterError from ex

        self.reader = csv.DictReader(preprocessed, dialect=dialect)

        # Could this happen?
        if self.reader.fieldnames is None:
            raise CsvNoDelimiterError

        # We support multiple options for address key, but exactly one must appear.
        addr_keys = [
            key for key in self.reader.fieldnames if key in ("address", "addr")
        ]
        if not addr_keys:
            raise CsvNoAddressError

        if len(addr_keys) > 1:
            raise CsvMultipleAddressError

        self.addr_key = addr_keys[0]

    def __iter__(self) -> "ReccmpCsvReader":
        return self

    def __next__(self) -> tuple[int, CsvValuesType]:
        row = next(self.reader)
        line_number = self.line_number_map.get(self.reader.line_num, -1)
        try:
            return _csv_convert(self.addr_key, row)
        except ReccmpCsvParserError as ex:
            # Set the line number here so we don't have to pass it down to
            # every function that could raise an exception.
            ex.line_number = line_number
            raise ex


def csv_parse(lines: str | Iterable[str]) -> ReccmpCsvReader:
    return ReccmpCsvReader(lines)
