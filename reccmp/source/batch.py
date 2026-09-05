"""Parallel direct-record collection for native and container compile databases."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
from typing import Mapping, Sequence

from reccmp.parser.marker import ProjectAliases
from .index import SourceCollector, SourceIndex, SourceIndexError, ast_command

_SOURCE = Path(__file__).with_name("indexer.cpp")
_COMPILE = (
    "clang++ -O2 -std=c++17 -fno-rtti -fno-exceptions"
    " -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS"
    " -I/usr/lib/llvm-14/include {source} -o {output}"
    " /usr/lib/llvm-14/lib/libclang-cpp.so.14"
    " /usr/lib/x86_64-linux-gnu/libLLVM-14.so.1"
)


def record_command(entry: dict, indexer: str, clang: str | None = None) -> list[str]:
    """Replay build arguments, replacing the whole-AST dump with direct records."""
    arguments = ast_command(entry, clang, ())
    position = arguments.index("-ast-dump=json")
    del arguments[position - 1 : position + 1]
    return [indexer, *arguments]


def _run(command: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(
        command, capture_output=True, text=True, check=False, **kwargs
    )
    if result.returncode:
        raise SourceIndexError(
            f"source index command failed ({result.returncode}): {shlex.join(command)}\n{result.stderr}"
        )
    return result


# Execution options describe the compile environment directly, without a plugin layer.
# pylint: disable=too-many-arguments,too-many-locals
def collect_compile_database(
    repository: Path,
    compilation_database: Path,
    targets: Mapping[str, Sequence[Path]],
    *,
    clang: str | None,
    jobs: int | None,
    container_image: str | None,
    mounts: Mapping[Path, str] | None,
    compilation_root: Path | None,
    cache_dir: Path | None,
    cache_inputs: Sequence[Path],
    force: bool,
    aliases: ProjectAliases | None,
) -> SourceIndex:
    repository = repository.resolve()
    mounts = mounts or {}
    root = str(compilation_root or repository)
    cache = (cache_dir or repository / "build/reccmp-source").resolve()
    cache.mkdir(parents=True, exist_ok=True)
    # Serialize builders sharing a cache so a cancelled or concurrent rebuild
    # cannot expose a partially-written executable or JSON projection.
    with (cache / "lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        database = json.loads(compilation_database.read_text(encoding="utf-8"))
        if jobs is not None and jobs < 1:
            raise ValueError("source index jobs must be positive")
        parallelism = min(len(database), jobs or os.cpu_count() or 1) or 1
        if container_image:
            compiler_identity = _run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", container_image]
            ).stdout.strip()
        else:
            compiler_identity = _run(["clang++", "--version"]).stdout
        binary_digest = hashlib.sha256(
            (_COMPILE + compiler_identity).encode() + _SOURCE.read_bytes()
        ).hexdigest()
        fingerprint = hashlib.sha256()
        options = (
            database,
            root,
            clang,
            binary_digest,
            {str(path): value for path, value in mounts.items()},
            {key: [str(path) for path in paths] for key, paths in targets.items()},
            aliases,
        )
        fingerprint.update(json.dumps(options, sort_keys=True).encode())
        implementation = [
            *_SOURCE.parent.glob("*.py"),
            *(_SOURCE.parents[1] / "parser").glob("*.py"),
        ]
        for path in sorted(implementation):
            fingerprint.update(path.read_bytes())
        inputs = {path for paths in targets.values() for path in paths}
        for path in cache_inputs:
            if path.is_dir():
                inputs.update(item for item in path.rglob("*") if item.is_file())
            else:
                inputs.add(path)
        for path in sorted(inputs):
            fingerprint.update(str(path).encode() + b"\0" + path.read_bytes() + b"\0")
        digest = fingerprint.hexdigest()
        stamp = cache / "inputs.sha256"
        projection = cache / "source-index.json"
        # No header list means dependencies are unknown; don't cache a potentially
        # stale index. The compiled collector itself can still be reused.
        if (
            cache_inputs
            and not force
            and projection.is_file()
            and stamp.is_file()
            and stamp.read_text() == digest
        ):
            return SourceIndex.from_dict(
                json.loads(projection.read_text(encoding="utf-8"))
            )

        binary = cache / "indexer"
        binary_stamp = cache / "indexer.sha256"
        container = [
            "docker",
            "run",
            "--rm",
            "--init",
            "--network",
            "none",
            "--env",
            "TMPDIR=/tmp",
        ]
        if (
            not binary.is_file()
            or not binary_stamp.is_file()
            or binary_stamp.read_text() != binary_digest
        ):
            if container_image:
                _run(
                    [
                        *container,
                        "--volume",
                        f"{_SOURCE.parent}:/reccmp-source:ro",
                        "--volume",
                        f"{cache}:/reccmp-cache",
                        "--entrypoint",
                        "/bin/sh",
                        container_image,
                        "-c",
                        _COMPILE.format(
                            source="/reccmp-source/indexer.cpp",
                            output="/reccmp-cache/indexer",
                        ),
                    ]
                )
            else:
                _run(
                    shlex.split(
                        _COMPILE.format(
                            source=shlex.quote(str(_SOURCE)),
                            output=shlex.quote(str(binary)),
                        )
                    )
                )
            binary_stamp.write_text(binary_digest, encoding="utf-8")

        collector = SourceCollector(repository, Path(root))
        with tempfile.TemporaryDirectory(prefix="batch-", dir=cache) as raw:
            scratch = Path(raw)
            if container_image and database:
                for index, entry in enumerate(database):
                    command = shlex.join(
                        record_command(entry, "/reccmp-cache/indexer", clang)
                    )
                    (scratch / f"{index:05d}.sh").write_text(
                        f"cd {shlex.quote(entry['directory'])} || exit\n"
                        f"{command} > /reccmp-batch/{index:05d}.ndjson 2> /reccmp-batch/{index:05d}.err\n"
                        f"echo $? > /reccmp-batch/{index:05d}.status\n",
                        encoding="utf-8",
                    )
                volumes = [
                    arg
                    for host, guest in mounts.items()
                    for arg in ("--volume", f"{host}:{guest}:ro")
                ]
                _run(
                    [
                        *container,
                        *volumes,
                        "--env",
                        f"RECCMP_SOURCE_ROOT={root}",
                        "--volume",
                        f"{cache}:/reccmp-cache:ro",
                        "--volume",
                        f"{scratch}:/reccmp-batch",
                        "--entrypoint",
                        "/bin/sh",
                        container_image,
                        "-c",
                        f"printf '%s\\n' /reccmp-batch/*.sh | xargs -P {parallelism} -n 1 /bin/sh",
                    ]
                )
            elif database:

                def emit(unit):
                    index, entry = unit
                    with (
                        (scratch / f"{index:05d}.ndjson").open("w") as out,
                        (scratch / f"{index:05d}.err").open("w") as err,
                    ):
                        result = subprocess.run(
                            record_command(entry, str(binary), clang),
                            cwd=entry["directory"],
                            stdout=out,
                            stderr=err,
                            env={**os.environ, "RECCMP_SOURCE_ROOT": root},
                            check=False,
                        )
                    (scratch / f"{index:05d}.status").write_text(str(result.returncode))

                with ThreadPoolExecutor(max_workers=parallelism) as executor:
                    list(executor.map(emit, enumerate(database)))
            for index, entry in enumerate(database):
                status = scratch / f"{index:05d}.status"
                if not status.is_file() or status.read_text().strip() != "0":
                    error = scratch / f"{index:05d}.err"
                    detail = (
                        error.read_text(errors="replace")
                        if error.is_file()
                        else "no compiler result"
                    )
                    raise SourceIndexError(
                        f"the source indexer failed on {entry['file']}: {detail}"
                    )
                with (scratch / f"{index:05d}.ndjson").open(
                    encoding="utf-8"
                ) as records:
                    for line in records:
                        if line.strip():
                            collector.collect_record(json.loads(line))
        indexes = [
            SourceIndex.from_collector(
                repository, target, paths, collector, aliases=aliases
            )
            for target, paths in targets.items()
        ]
        result_index = SourceIndex(
            declarations=(item for part in indexes for item in part.declarations),
            classes=(item for part in indexes for item in part.classes),
            markers=(item for part in indexes for item in part.markers),
        )
        result_index.write(projection)
        stamp.write_text(digest, encoding="utf-8")
        return result_index
