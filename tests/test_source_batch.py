"""Exercise the actual collector with an explicitly selected LLVM 14 image."""

import json
import os
from pathlib import Path

import pytest

from reccmp.source import SourceIndex, SourceIndexError


def test_container_batch_records_cache_and_errors(tmp_path: Path) -> None:
    image = os.environ.get("RECCMP_SOURCE_TEST_IMAGE")
    if not image:
        pytest.skip(
            "set RECCMP_SOURCE_TEST_IMAGE to an image with LLVM 14 development libraries"
        )
    repository = tmp_path / "source with spaces"
    repository.mkdir()
    header = repository / "owner.h"
    header.write_text(
        "struct Owner {\n"
        "  int **pointers;\n"
        "  int (*callback)(int);\n"
        "  int *elements[2];\n"
        "  int &reference;\n"
        '};\nstatic_assert(sizeof(Owner) == 20, "size");\n',
        encoding="utf-8",
    )
    sources = [repository / name for name in ("first.cpp", "second.cpp", "empty.cpp")]
    for path, target in zip(sources, ("FIRST", "SECOND")):
        path.write_text(
            '#include "owner.h"\n'
            f"// FUNCTION: {target} 0x00401000\n"
            f"int {target}() {{ return 0; }}\n",
            encoding="utf-8",
        )
    sources[2].write_text(
        "// A successful unit may emit no records.\n", encoding="utf-8"
    )
    database = repository / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {
                    "directory": "/repo",
                    "file": "/repo/" + path.name,
                    "arguments": [
                        "/usr/bin/clang-cl",
                        "--target=i686-pc-windows-msvc",
                        "/c",
                        "/repo/" + path.name,
                    ],
                }
                for path in sources
            ]
        ),
        encoding="utf-8",
    )
    cache = tmp_path / "cache with spaces"

    def collect():
        return SourceIndex.from_compile_database(
            repository,
            database,
            {"FIRST": [header, sources[0]], "SECOND": [sources[1]]},
            container_image=image,
            mounts={repository: "/repo"},
            compilation_root=Path("/repo"),
            cache_dir=cache,
            cache_inputs=[header, *sources],
            jobs=2,
        )

    index = collect()
    assert len(index.classes) == 1
    assert index.classes[0].asserted_size == 20
    assert [field.pointer_depth for field in index.classes[0].fields] == [2, 1, 0, 0]
    assert index.functions_by_address(target="FIRST")[0x401000].name == "FIRST"
    assert index.functions_by_address(target="SECOND")[0x401000].name == "SECOND"
    assert (
        SourceIndex.from_dict(json.loads(json.dumps(index.to_dict()))).to_dict()
        == index.to_dict()
    )
    stamp = cache / "inputs.sha256"
    before = stamp.stat().st_mtime_ns
    assert collect().to_dict() == index.to_dict()
    assert stamp.stat().st_mtime_ns == before
    header.write_text(
        header.read_text().replace("**pointers", "*pointers"), encoding="utf-8"
    )
    assert collect().classes[0].fields[0].pointer_depth == 1
    assert stamp.stat().st_mtime_ns != before
    sources[0].write_text("this is not valid C++;\n", encoding="utf-8")
    with pytest.raises(SourceIndexError, match="first.cpp"):
        collect()
