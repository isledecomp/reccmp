# Compiler-backed source index

`SourceIndex.from_compile_database()` collects declarations and layouts directly
from Clang, in parallel, then binds reccmp markers to those records. It replaces
the serial `from_compilation_database` and `from_compilation_database_targets`
APIs. No whole-AST JSON files or downstream collector subclasses are needed.

```python
from pathlib import Path
from reccmp.source import SourceIndex

repo = Path.cwd()
index = SourceIndex.from_compile_database(
    repo,
    repo / "build/compile_commands.json",
    {"GAME": list((repo / "src").rglob("*.cpp")) + list((repo / "include").rglob("*.h"))},
    cache_inputs=[repo / "src", repo / "include"],
    jobs=4,
)
index.write(repo / "build/source-index.json")
owners = index.functions_by_address(target="GAME")
```

The collector currently builds against the Linux LLVM 14 development libraries
(`clang++`, `/usr/lib/llvm-14`, `libclang-cpp.so.14`, and `libLLVM-14.so.1`).
Its C++ source ships in the Python package; the executable stays in the project's
disposable cache. Native commands use each compile entry's working directory.
For container compile databases, pass `container_image`, `mounts={host_path:
"/container/path"}`, and `compilation_root=Path("/container/repo")`. The whole
batch runs in one container with the supplied mounts read-only. `clang` optionally
overrides the compiler named in the database. No emitter or plugin hooks exist.

`cache_inputs` must cover all headers and other dependencies used by the commands,
including external header roots. File contents, compile arguments, marker paths,
collector implementation, and the actual image ID invalidate the cache. Without
explicit dependency inputs only the collector executable is cached. `force=True`
refreshes the index. Concurrent builders serialize through the cache lock; compiler
failures include the translation unit and diagnostics. Empty successful output is
valid. Writing an unchanged index preserves its file timestamp.

Records retain compiler-owned source signatures, parameter reference forms, and
field pointer depth (arrays and references are not peeled). Markers retain their
target and folded status. `SourceIndex.from_dict()` reads the JSON projection back
into these same types; `functions_by_address(target=...)` selects the unfolded
owner and refuses ambiguous ownership. Use `marker.declaration` for function
semantics and `marker.name` for either a declaration or a named non-body emission.

For already-collected data, `SourceCollector.collect_record()` accepts one
declaration, class, or size-assertion record; `collect_records()` accepts NDJSON.
Definitions replace declarations, the first located class wins, and conflicting
size assertions are errors. Neither method mutates the supplied record.
`SourceIndex.from_collector()` performs the marker join. `ast_command()` exposes
the compile-argument normalization used by the direct-record collector.

Run `RECCMP_SOURCE_TEST_IMAGE=<image> uv run --group test pytest
tests/test_source_batch.py` to exercise actual compilation, multi-target ownership,
structured layouts, cache invalidation, empty units, and compiler errors.
