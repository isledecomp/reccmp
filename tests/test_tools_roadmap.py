"""Testing the reccmp-roadmap tool's CSV export.

Regression coverage for the unquoted-comma bug: `export_to_csv` used to build
each line with a bare `",".join(...)`, so any field containing a comma (most
commonly `name`, for a multi-argument template symbol like
`set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >`) produced a row with extra
columns once read back. In this project that silently invented dozens of fake
"modules" on the very first parse of a real dump.
"""

import csv

from reccmp.tools.roadmap import RoadmapRow, export_to_csv


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
    )


def test_export_to_csv_quotes_field_with_comma(tmp_path):
    """A field containing a comma (as in a multi-argument template symbol)
    must be quoted so a CSV reader recovers the original column count.

    Mutation proof: reverting `export_to_csv` to
    `f.write(",".join(map(or_blank, row)))` makes this fail two ways -- the
    row-back-in has more than `len(RoadmapRow._fields)` columns (the comma
    inside `name` gets read as two extra delimiters), and the recovered
    `name`/`module` values no longer match what was written.
    """
    template_name = "set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >"
    row = _make_row(name=template_name)

    csv_file = tmp_path / "roadmap.csv"
    export_to_csv(str(csv_file), [row])

    with open(csv_file, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        data_row = next(reader)

        # No further rows: a mis-split row here would otherwise bleed into
        # (and corrupt the column count of) whatever came next.
        assert next(reader, None) is None

    assert header == [
        "orig_sect_ofs",
        "recomp_sect_ofs",
        "orig_addr",
        "recomp_addr",
        "displacement",
        "row_type",
        "size",
        "name",
        "module",
    ]
    assert len(data_row) == len(RoadmapRow._fields)
    assert data_row[header.index("name")] == template_name
    assert data_row[header.index("module")] == "LEGO1/define.cpp"


def test_export_to_csv_multiple_rows_stay_aligned(tmp_path):
    """A comma-bearing field on one row must not shift the columns of
    subsequent rows once read back."""
    rows = [
        _make_row(name="foo<A,B>", module="ONE/a.cpp"),
        _make_row(name="bar", module="TWO/b.cpp"),
    ]

    csv_file = tmp_path / "roadmap.csv"
    export_to_csv(str(csv_file), rows)

    with open(csv_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        parsed = list(reader)

    assert len(parsed) == 2
    assert parsed[0]["name"] == "foo<A,B>"
    assert parsed[0]["module"] == "ONE/a.cpp"
    assert parsed[1]["name"] == "bar"
    assert parsed[1]["module"] == "TWO/b.cpp"


def test_export_to_csv_no_special_characters_unaffected(tmp_path):
    """Plain values without commas/quotes still round-trip exactly
    (no unwanted quoting introduced for the common case)."""
    row = _make_row(name="FUN_1000abcd", module="LEGO1/define.cpp")

    csv_file = tmp_path / "roadmap.csv"
    export_to_csv(str(csv_file), [row])

    with open(csv_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        parsed = list(reader)

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
        }
    ]
