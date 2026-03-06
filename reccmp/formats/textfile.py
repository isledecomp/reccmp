import logging
from pathlib import Path, PurePath
from typing import Iterable, Iterator, NamedTuple

logger = logging.getLogger(__name__)


class TextFile(NamedTuple):
    """Wrapper to abstract file access in cases where the filename or path has meaning.
    Once created, the `path` member should be used as a path-like string only.
    We can not assume there is a real file at that location."""

    path: PurePath
    text: str

    @classmethod
    def from_file(cls, path: Path, *, encoding: str = "utf-8") -> "TextFile":
        # Resolve the path here to remove any '..' references
        # and produce the most concise path-like string.
        path = path.resolve()
        with path.open("r", encoding=encoding) as f:
            return cls(path, f.read())

    @classmethod
    def from_files(
        cls,
        paths: Iterable[Path],
        *,
        encoding: str = "utf-8",
        allow_error: bool = False,
    ) -> Iterator["TextFile"]:
        """Wrapper for TextFile.from_file() that gives the opportunity to
        recover from some expected problems when this makes sense."""
        for path in paths:
            try:
                yield cls.from_file(path, encoding=encoding)

            except FileNotFoundError as ex:
                logger.error("Could not open '%s'", path)
                if not allow_error:
                    raise ex

            except UnicodeDecodeError as ex:
                logger.error(
                    "Failed to decode '%s' as %s (reason: %s, position: %d)",
                    path,
                    ex.encoding,
                    ex.reason,
                    ex.start,
                )
                if not allow_error:
                    raise ex
