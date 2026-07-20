"""Validated local cache for expensive, deterministic analysis inputs.

The cache deliberately stops before entity matching and semantic comparison.  A
cache hit can reuse parsed PDB or source-marker data, but every invocation still
rebuilds the entity database and executes the comparison verifier.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import logging
import os
from pathlib import Path
import pickle
import sys
import tempfile
from typing import Iterable, TypeVar, cast

from reccmp.formats import TextFile

logger = logging.getLogger(__name__)

_CACHE_SCHEMA = 1
_T = TypeVar("_T")


@dataclass(frozen=True)
class _CacheRecord:
    schema: int
    python_version: tuple[int, int]
    fingerprint: str
    value: object


def fingerprint_files(paths: Iterable[Path], *, context: str = "") -> str:
    """Hash file names and contents in deterministic order."""
    digest = hashlib.sha256()
    digest.update(context.encode("utf-8"))
    for path in sorted((path.resolve() for path in paths), key=str):
        digest.update(b"\0path\0")
        digest.update(str(path).encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0data\0")
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def fingerprint_text_files(files: Iterable[TextFile], *, context: str = "") -> str:
    """Hash already-loaded source files without reading them a second time."""
    digest = hashlib.sha256()
    digest.update(context.encode("utf-8"))
    for text_file in sorted(files, key=lambda f: str(f.path)):
        digest.update(b"\0path\0")
        digest.update(str(text_file.path).encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0data\0")
        digest.update(text_file.text.encode("utf-8", errors="surrogateescape"))
    return digest.hexdigest()


class AnalysisCache:
    """Small atomic pickle cache rooted beside the recompiled PDB."""

    def __init__(self, root: Path, *, enabled: bool = True) -> None:
        self.root = root
        self.enabled = enabled

    def _path(self, name: str) -> Path:
        if not name or any(
            char not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for char in name
        ):
            raise ValueError(f"Invalid analysis cache key: {name!r}")
        return self.root / f"{name}.pickle"

    def load(self, name: str, fingerprint: str) -> _T | None:
        if not self.enabled:
            return None
        path = self._path(name)
        try:
            with path.open("rb") as stream:
                record = pickle.load(stream)  # noqa: S301 - private local build cache
        except (
            FileNotFoundError,
            OSError,
            EOFError,
            pickle.PickleError,
            AttributeError,
            ImportError,
            IndexError,
            TypeError,
            ValueError,
        ):
            logger.debug("Analysis cache miss: %s", name)
            return None

        if not isinstance(record, _CacheRecord):
            logger.debug("Ignoring invalid analysis cache record: %s", name)
            return None
        if (
            record.schema != _CACHE_SCHEMA
            or record.python_version != sys.version_info[:2]
            or record.fingerprint != fingerprint
        ):
            logger.debug("Analysis cache fingerprint mismatch: %s", name)
            return None

        logger.debug("Analysis cache hit: %s", name)
        return cast(_T, record.value)

    def store(self, name: str, fingerprint: str, value: object) -> None:
        if not self.enabled:
            return
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            record = _CacheRecord(
                schema=_CACHE_SCHEMA,
                python_version=sys.version_info[:2],
                fingerprint=fingerprint,
                value=value,
            )
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.root, prefix=f".{name}-", delete=False
            ) as stream:
                temp_path = Path(stream.name)
                pickle.dump(record, stream, protocol=pickle.HIGHEST_PROTOCOL)
            os.replace(temp_path, self._path(name))
        except (OSError, pickle.PickleError, TypeError):
            logger.debug(
                "Could not write analysis cache entry: %s", name, exc_info=True
            )
            if "temp_path" in locals():
                temp_path.unlink(missing_ok=True)
