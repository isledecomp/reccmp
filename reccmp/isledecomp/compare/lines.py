"""Database used to match (filename, line_number) pairs
between FUNCTION markers and PDB analysis."""

import sqlite3
import logging
from functools import cache
from pathlib import Path, PurePath, PureWindowsPath
from collections.abc import Sequence
from typing import Iterator
from reccmp.isledecomp.dir import convert_foreign_path


logger = logging.getLogger(__name__)

_SETUP_SQL = """
    CREATE table lines (
        addr integer not null primary key,
        file integer not null,
        lineno integer not null,
        start integer not null default 0
    ) without rowid;
"""


@cache
def get_file_hash(filepath: str | Path | PurePath) -> int:
    # This check is required for cross-platform tests.
    # Don't convert a PurePosixPath back to PureWindowsPath if we are testing on a Windows host.
    if isinstance(filepath, PurePath):
        return hash(filepath)

    return hash(PurePath(filepath))


class LinesDb:
    def __init__(
        self, files: Sequence[Path] | Sequence[PurePath] | Sequence[str]
    ) -> None:
        self._path_resolver = cache(convert_foreign_path)

        self._db = sqlite3.connect(":memory:")
        self._db.executescript(_SETUP_SQL)

        self._indexed = False

        # Set up memoized map of filenames to their paths
        self._filenames: dict[str, list[PurePath]] = {}
        for path in files:
            if not isinstance(path, PurePath):
                path = PurePath(path)

            self._filenames.setdefault(path.name.lower(), []).append(path)

    def add_line(self, foreign_path: PureWindowsPath, line_no: int, addr: int):
        """Connect the remote path to a line number and address pair."""
        return self.add_lines(foreign_path, ((line_no, addr),))

    def add_lines(
        self, foreign_path: PureWindowsPath, lines: Sequence[tuple[int, int]]
    ):
        """Connect the remote path to a line number and address pair."""
        filename = foreign_path.name.lower()

        candidates = self._filenames.get(filename)
        if candidates is None:
            return

        # Must convert to tuple (hashable type) so we can use functools.cache
        sourcepath = self._path_resolver(foreign_path, tuple(candidates))
        if sourcepath is None:
            return

        path_hash = hash(sourcepath)

        self._db.executemany(
            "INSERT into lines (addr, file, lineno) values (?,?,?)",
            ((addr, path_hash, line_no) for (line_no, addr) in lines),
        )

    def mark_function_starts(self, addrs: Sequence[int]):
        self._db.executemany(
            "UPDATE lines SET start = 1 WHERE addr = ?", ((addr,) for addr in addrs)
        )

    def search_line(
        self,
        local_path: str | Path | PurePath,
        line_start: int,
        line_end: int | None = None,
        start_only: bool = False,
    ) -> Iterator[int]:
        # Add the index here, right before it's needed,
        # so we don't incur overhead while inserting lines.
        if not self._indexed:
            self._db.execute("CREATE index idx_file_line on lines (file, lineno)")
            self._indexed = True

        # If there is no end line, search for a single line only
        if line_end is None:
            line_end = line_start

        path_hash = get_file_hash(local_path)

        for (addr,) in self._db.execute(
            """
            SELECT addr from lines
            where file = ? and lineno >= ? and lineno <= ?
            and (0 = ? or start = 1)""",
            (path_hash, line_start, line_end, start_only),
        ):
            yield addr

    def find_function(
        self,
        local_path: str | Path | PurePath,
        line_start: int,
        line_end: int | None = None,
    ) -> int | None:
        """The database contains the first line of each function, as verified by
        reducing the starting list of line-offset pairs using other information from the pdb.
        We want to know if exactly one function exists between line start and line end
        in the given file."""

        possible_functions = [
            *self.search_line(local_path, line_start, line_end, start_only=True)
        ]

        if len(possible_functions) == 1:
            return possible_functions[0]

        # The file has been edited since the last compile.
        if len(possible_functions) > 1:
            logger.error(
                "Debug data out of sync with function near: %s:%d",
                local_path,
                line_start,
            )
            return None

        # No functions matched. This could mean the file is out of sync, or that
        # the function was eliminated or inlined by compiler optimizations.
        logger.error(
            "Failed to find function symbol with filename and line: %s:%d",
            local_path,
            line_start,
        )
        return None
