"""Database used to match (filename, line_number) pairs
between FUNCTION markers and PDB analysis."""

import sqlite3
import logging
from functools import cache
from pathlib import Path
from reccmp.isledecomp.dir import PathResolver


_SETUP_SQL = """
    CREATE TABLE lineref (
        path text not null,
        filename text not null,
        line int not null,
        addr int not null
    );
    CREATE INDEX file_line ON lineref (filename, line);
"""


logger = logging.getLogger(__name__)


@cache
def my_samefile(path: str, source_path: str) -> bool:
    return Path(path).samefile(source_path)


@cache
def my_basename_lower(path: str) -> str:
    return Path(path).name.lower()


class LinesDb:
    def __init__(self, code_dir) -> None:
        self._db = sqlite3.connect(":memory:")
        self._db.executescript(_SETUP_SQL)
        self._path_resolver = PathResolver(code_dir)

    def add_line(self, path: str, line_no: int, addr: int):
        """To be added from the LINES section of cvdump."""
        sourcepath = self._path_resolver.resolve_cvdump(path)
        filename = my_basename_lower(sourcepath)

        self._db.execute(
            "INSERT INTO lineref (path, filename, line, addr) VALUES (?,?,?,?)",
            (sourcepath, filename, line_no, addr),
        )

    def search_line(
        self, path: str, line_start: int, line_end: int | None = None
    ) -> int | None:
        """The database contains the first line of each function, as verified by
        reducing the starting list of line-offset pairs using other information from the pdb.
        We want to know if exactly one function exists between line start and line end
        in the given file."""

        # We might not capture the end line of a function. If not, search for the start line only.
        if line_end is None:
            line_end = line_start

        # Search using the filename from the path to limit calls to Path.samefile.
        # TODO: This should be refactored. Maybe sqlite isn't suited for this and we
        # should store Path objects as dict keys instead.
        filename = my_basename_lower(path)
        cur = self._db.execute(
            "SELECT path, addr FROM lineref WHERE filename = ? AND line >= ? AND line <= ?",
            (filename, line_start, line_end),
        )

        possible_functions = [
            addr for source_path, addr in cur if my_samefile(path, source_path)
        ]
        if len(possible_functions) == 1:
            return possible_functions[0]

        # The file has been edited since the last compile.
        if len(possible_functions) > 1:
            logger.error(
                "Debug data out of sync with function near: %s:%d",
                path,
                line_start,
            )
            return None

        # No functions matched. This could mean the file is out of sync, or that
        # the function was eliminated or inlined by compiler optimizations.
        logger.error(
            "Failed to find function symbol with filename and line: %s:%d",
            path,
            line_start,
        )
        return None
