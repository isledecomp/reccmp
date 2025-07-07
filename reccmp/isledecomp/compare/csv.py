"""Parsing files in csv format.
The python csv.DictReader class does the heavy lifting.
We begin with a pre-processing step that removes blank lines or "comment" lines that begin with # or //.
The delimiter is decided based on the first line (following pre-processing). Options are: pipe, comma, tab
"""

import csv
from csv import Error as PythonCsvError
from typing import Iterable, Iterator


class ReccmpCsvParserError(Exception):
    """Catch-all for csv parsing errors."""


class CsvNoAddressError(ReccmpCsvParserError):
    """This row does not have an address attribute."""


class CsvMultipleAddressError(ReccmpCsvParserError):
    """This row has more than one address attribute
    (and it's not clear which one we should use)."""


class CsvInvalidAddressError(ReccmpCsvParserError):
    """The address value is not a valid hex number."""


class CsvNoDelimiterError(ReccmpCsvParserError):
    """No obvious delimiter on the first line."""


CsvValueOptions = int | str | bool
CsvValuesType = dict[str, CsvValueOptions]


def _boolify(text: str) -> bool:
    """str to bool conversion. If the string is not in the exclusion list, resolve to True."""
    return text.strip().lower() not in ("false", "off", "no", "0", "")


def _csv_preprocess(lines: Iterable[str]) -> Iterator[str]:
    """Pre-processing of CSV file."""
    for line in lines:
        strip = line.strip()
        # Skip comment lines
        if strip.startswith("#") or strip.startswith("//"):
            continue

        # Skip blank lines.
        if strip == "":
            continue

        yield line


def _convert_attrs(
    values: Iterable[tuple[str, str]],
) -> Iterator[tuple[str, CsvValueOptions]]:
    """Both a filter and a conversion step for the row values.
    For the incoming iterable of key/value pairs, only output the ones we want set
    in the reccmp database. Some keys have their value converted to a different type."""
    for key, value in values:
        if key == "symbol":
            yield (key, value)

        if key == "skip":
            yield (key, _boolify(value))


def _csv_convert(addr_key: str, row: dict[str, str]) -> tuple[int, CsvValuesType]:
    """Pull out the address from the CSV row and convert the remaining key/value pairs."""
    try:
        # Addr is always a hex number
        addr_value = row[addr_key]
        addr = int(addr_value, 16)
    except ValueError as ex:
        raise CsvInvalidAddressError from ex

    attrs = list(_convert_attrs(row.items()))
    return (addr, dict(attrs))


def csv_parse(lines: str | Iterable[str]) -> Iterator[tuple[int, CsvValuesType]]:
    """Read each line from the csv file and output each address and its key/value pairs."""
    if isinstance(lines, str):
        lines = lines.split("\n")

    preprocessed = list(_csv_preprocess(lines))

    try:
        # Use the first line (only) to find the delimiter
        dialect = csv.Sniffer().sniff(preprocessed[0], delimiters="|,\t")
    except PythonCsvError as ex:
        raise CsvNoDelimiterError from ex

    reader = csv.DictReader(preprocessed, dialect=dialect)

    # Could this happen?
    if reader.fieldnames is None:
        raise CsvNoDelimiterError

    # We support multiple options for address key, but exactly one must appear.
    addr_keys = [key for key in reader.fieldnames if key in ("address", "addr")]
    if not addr_keys:
        raise CsvNoAddressError

    if len(addr_keys) > 1:
        raise CsvMultipleAddressError

    for row in reader:
        yield _csv_convert(addr_keys[0], row)
