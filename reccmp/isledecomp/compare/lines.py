"""Database used to match (filename, line_number) pairs
between FUNCTION markers and PDB analysis."""

import logging
from functools import cache
from pathlib import Path, PurePath, PureWindowsPath
from collections.abc import Sequence
from reccmp.isledecomp.dir import convert_foreign_path


logger = logging.getLogger(__name__)


class LinesDb:
    def __init__(
        self, files: Sequence[Path] | Sequence[PurePath] | Sequence[str]
    ) -> None:
        self._path_resolver = cache(convert_foreign_path)

        # Set up memoized map of filenames to their paths
        self._filenames: dict[str, list[PurePath]] = {}
        for path in files:
            if not isinstance(path, PurePath):
                path = PurePath(path)

            self._filenames.setdefault(path.name.lower(), []).append(path)

        # Local filename to list of (line_no, address) pairs
        # This has to be a list instead of a dict because line numbers may be used twice.
        # e.g. for the start and end of a loop.
        self._map: dict[PurePath, list[tuple[int, int]]] = {}

    def add_line(self, foreign_path: str, line_no: int, addr: int):
        """Connect the remote path to a line number and address pair."""
        pdb_path = PureWindowsPath(foreign_path)
        filename = pdb_path.name.lower()

        candidates = self._filenames.get(filename)
        if candidates is None:
            return

        # Must convert to tuple (hashable type) so we can use functools.cache
        sourcepath = self._path_resolver(pdb_path, tuple(candidates))
        if sourcepath is None:
            return

        self._map.setdefault(sourcepath, []).append((line_no, addr))

    def search_line(
        self,
        local_path: str | Path | PurePath,
        line_start: int,
        line_end: int | None = None,
    ) -> int | None:
        """The database contains the first line of each function, as verified by
        reducing the starting list of line-offset pairs using other information from the pdb.
        We want to know if exactly one function exists between line start and line end
        in the given file."""

        # We might not capture the end line of a function. If not, search for the start line only.
        if line_end is None:
            line_end = line_start

        if not isinstance(local_path, PurePath):
            local_path = PurePath(local_path)

        lines = self._map.get(local_path)
        if lines is None:
            return None

        lines.sort()

        possible_functions = [
            addr for (line_no, addr) in lines if line_start <= line_no <= line_end
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
