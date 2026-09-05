"""Tests for the reccmp-roadmap tool's CSV export."""

import csv
from pathlib import Path

from reccmp.tools.roadmap import RoadmapRow, export_to_csv, match_type_abbreviation
from reccmp.types import EntityType


def _make_row(name: str, module: str = "LEGO1/define.cpp") -> RoadmapRow:
    return RoadmapRow(
        orig_sect_ofs="0001:00001000",
        recomp_sect_ofs="0001:00001000",
        orig_addr=0x1000,
        recomp_addr=0x1000,
        displacement=0,
        sym_type="fun",
        size=16,
        name=name,
        module=module,
        pairing_state="paired",
    )


def _write_and_read_back(tmp_path: Path, rows: list[RoadmapRow]) -> list[dict]:
    """Export the rows to a CSV file, then parse the file back into a list
    of dicts keyed by the header columns."""
    csv_file = tmp_path / "roadmap.csv"
    export_to_csv(str(csv_file), rows)

    with open(csv_file, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_export_to_csv_quotes_field_with_comma(tmp_path):
    """A field with a comma in it (like a multi-argument template symbol)
    has to be quoted so a CSV reader gets the original columns back."""
    template_name = "set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >"
    row = _make_row(name=template_name)

    parsed = _write_and_read_back(tmp_path, [row])

    assert len(parsed) == 1
    assert parsed[0]["name"] == template_name
    assert parsed[0]["module"] == "LEGO1/define.cpp"


def test_export_to_csv_multiple_rows_stay_aligned(tmp_path):
    """A comma in one row shouldn't shift the columns of the rows after
    it."""
    rows = [
        _make_row(name="foo<A,B>", module="ONE/a.cpp"),
        _make_row(name="bar", module="TWO/b.cpp"),
    ]

    parsed = _write_and_read_back(tmp_path, rows)

    assert len(parsed) == 2
    assert parsed[0]["name"] == "foo<A,B>"
    assert parsed[0]["module"] == "ONE/a.cpp"
    assert parsed[1]["name"] == "bar"
    assert parsed[1]["module"] == "TWO/b.cpp"


def test_export_to_csv_no_special_characters_unaffected(tmp_path):
    """Values with no comma or quote in them (the common case) come back
    from the parser exactly as they went in."""
    row = _make_row(name="FUN_1000abcd", module="LEGO1/define.cpp")

    parsed = _write_and_read_back(tmp_path, [row])

    assert parsed == [
        {
            "orig_sect_ofs": "0001:00001000",
            "recomp_sect_ofs": "0001:00001000",
            "orig_addr": "0x1000",
            "recomp_addr": "0x1000",
            "displacement": "0x0",
            "row_type": "fun",
            "size": "0x10",
            "name": "FUN_1000abcd",
            "module": "LEGO1/define.cpp",
            "pairing_state": "paired",
        }
    ]


def test_import_thunk_has_distinct_abbreviation():
    assert match_type_abbreviation(EntityType.IMPORT) == "imp"
    assert match_type_abbreviation(EntityType.IMPORT_THUNK) == "ith"
