import json
from pathlib import Path

import pytest
from reccmp.source.index import SourceIndexError
from reccmp.source import SourceCollector
from reccmp.source.batch import record_command

DECLARATION = {
    "record": "declaration",
    "semantic_id": "?Grow@Vector@@QAEHH@Z",
    "qualified_name": "Vector::Grow",
    "semantic_kind": "instance_method",
    "calling_convention": "__thiscall",
    "return_type": "int",
    "parameter_types": ["int"],
    "source_signature": "int Vector::Grow(int value)",
    "parameter_references": [False],
    "owning_class": "Vector",
    "has_this": True,
    "is_virtual": False,
    "source_file": "include/wiz8/vector.h",
    "line": 20,
    "end_line": 20,
    "is_definition": False,
}
CLASS = {
    "record": "class",
    "semantic_id": "record:Vector",
    "qualified_name": "Vector",
    "bases": [],
    "fields": [
        {
            "name": "count",
            "type": "int",
            "source_file": "include/wiz8/vector.h",
            "line": 24,
        }
    ],
    "virtual_declarations": [],
    "source_file": "include/wiz8/vector.h",
    "line": 12,
    "end_line": 30,
}


def _records(*records: dict) -> str:
    return "".join(json.dumps(record) + "\n" for record in records)


def test_definition_replaces_a_declaration_from_another_unit() -> None:
    collector = SourceCollector(Path("/repo"))
    definition = {**DECLARATION, "is_definition": True, "line": 105, "end_line": 118}
    collector.collect_records(_records(DECLARATION))
    collector.collect_records(_records(definition))
    collector.collect_records(_records(DECLARATION))

    kept = collector.declarations["?Grow@Vector@@QAEHH@Z"]
    assert kept.is_definition
    assert (kept.line, kept.end_line) == (105, 118)
    assert kept.parameter_types == ("int",)
    assert kept.source_signature == "int Vector::Grow(int value)"
    assert kept.parameter_references == (False,)


def test_class_is_kept_from_the_first_unit_that_located_it() -> None:
    collector = SourceCollector(Path("/repo"))
    collector.collect_records(_records({**CLASS, "line": 0, "end_line": 0}))
    collector.collect_records(_records(CLASS))
    collector.collect_records(_records({**CLASS, "line": 99, "end_line": 99}))

    kept = collector.classes["record:Vector"]
    assert (kept.line, kept.end_line) == (12, 30)
    assert kept.fields[0].name == "count"


def test_conflicting_size_assertions_are_refused() -> None:
    collector = SourceCollector(Path("/repo"))
    assertion = {
        "record": "size-assertion",
        "qualified_name": "Vector",
        "asserted_size": 16,
    }
    collector.collect_records(_records(assertion))
    collector.collect_records(_records(assertion))
    assert collector.size_assertions == {"Vector": 16}

    with pytest.raises(SourceIndexError, match="conflicting size assertions"):
        collector.collect_records(_records({**assertion, "asserted_size": 20}))


def test_an_unknown_record_is_refused_rather_than_ignored() -> None:
    collector = SourceCollector(Path("/repo"))
    with pytest.raises(SourceIndexError, match="unknown record"):
        collector.collect_records(
            _records({"record": "enum", "qualified_name": "Slot"})
        )


def test_the_index_command_keeps_the_build_arguments_and_drops_the_ast_dump() -> None:
    command = record_command(
        {
            "directory": "/out",
            "file": "/repo/src/wiz8/vector.cpp",
            "command": (
                "/usr/bin/clang-cl /nologo -Xclang -fno-wchar /Fovector.obj /c "
                "-- /repo/src/wiz8/vector.cpp"
            ),
        },
        "/indexer/indexer",
        "/usr/bin/clang-cl",
    )

    assert command[:2] == ["/indexer/indexer", "/usr/bin/clang-cl"]
    assert "-ast-dump=json" not in command
    # The build's own -Xclang option and its argument both survive, and the
    # source file stays behind the driver's end-of-options separator.
    assert command.count("-Xclang") == 1
    assert command[command.index("-Xclang") + 1] == "-fno-wchar"
    assert command[-2:] == ["--", "/repo/src/wiz8/vector.cpp"]
    assert not any(
        argument.startswith("/Fo") or argument == "/c" for argument in command
    )
