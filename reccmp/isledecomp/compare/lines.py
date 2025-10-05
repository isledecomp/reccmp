"""Database used to match (filename, line_number) pairs
between FUNCTION markers and PDB analysis."""

import logging
from functools import cache
from pathlib import Path, PurePath, PureWindowsPath
from typing import Iterable, Iterator
from reccmp.isledecomp.dir import convert_foreign_path


logger = logging.getLogger(__name__)


class LinesDb:
    # pylint: disable=too-many-instance-attributes
    def __init__(self) -> None:
        self._new_data = False
        self._path_resolver = cache(convert_foreign_path)

        self._path_queue: list[Path | PurePath] = []
        self._line_queue: list[tuple[PureWindowsPath, list[tuple[int, int]]]] = []

        # Set up memoized map of filenames to their paths
        self._filenames: dict[str, list[PurePath]] = {}

        # Local filename to list of (line_no, address) pairs
        # This has to be a list instead of a dict because line numbers may be used twice.
        # e.g. for the start and end of a loop.
        self._path_to_lines_and_addresses: dict[PurePath, list[tuple[int, int]]] = {}
        self._address_to_path_and_line: dict[int, tuple[PurePath, int]] = {}

        # Addresses for the first line for a function
        self._function_starts: set[int] = set()

    def add_files(self, paths: Iterable[Path] | Iterable[PurePath]):
        self._new_data = True
        self._path_queue.extend(paths)

    def add_line(self, foreign_path: PureWindowsPath, line_no: int, addr: int):
        """Connect the remote path to a line number and address pair."""
        return self.add_lines(foreign_path, ((line_no, addr),))

    def add_lines(
        self, foreign_path: PureWindowsPath, lines: Iterable[tuple[int, int]]
    ):
        """
        Connect the remote path to a line number and address pair.
        """
        self._new_data = True
        self._line_queue.append((foreign_path, list(lines)))

    def mark_function_starts(self, addrs: Iterable[int]):
        self._function_starts = self._function_starts.union(set(addrs))

    def _process(self):
        """Defer processing until we need results. This allows us to call add_files()
        and add_line() or add_lines() in any order up to the point where we search."""
        for path in self._path_queue:
            self._filenames.setdefault(path.name.lower(), []).append(path)

        # Don't remove from lines queue if we can't find a match.
        retry_lines = []

        for foreign_path, lines in self._line_queue:
            filename = foreign_path.name.lower()

            candidates = self._filenames.get(filename)
            if candidates is None:
                retry_lines.append((foreign_path, lines))
                continue

            # Must convert to tuple (hashable type) so we can use functools.cache
            sourcepath = self._path_resolver(foreign_path, tuple(candidates))
            if sourcepath is None:
                retry_lines.append((foreign_path, lines))
                continue

            self._path_to_lines_and_addresses.setdefault(sourcepath, []).extend(
                list(lines)
            )
            for line_number, address in lines:
                self._address_to_path_and_line[address] = (sourcepath, line_number)

        self._path_queue.clear()
        self._line_queue.clear()
        self._line_queue.extend(retry_lines)
        self._new_data = False

    def search_line(
        self,
        local_path: str | Path | PurePath,
        line_start: int,
        line_end: int | None = None,
        start_only: bool = False,
    ) -> Iterator[int]:
        if self._new_data:
            self._process()

        # If there is no end line, search for a single line only
        if line_end is None:
            line_end = line_start

        if not isinstance(local_path, PurePath):
            local_path = PurePath(local_path)

        for line_no, addr in self._path_to_lines_and_addresses.get(local_path, []):
            if (line_start <= line_no <= line_end) and (
                not start_only or addr in self._function_starts
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

        possible_functions = set(
            self.search_line(local_path, line_start, line_end, start_only=True)
        )

        if len(possible_functions) == 1:
            return next(iter(possible_functions))

        # The functions in the code do not match the PDB, likely because the file has been edited since the last compile.
        if len(possible_functions) > 1:
            logger.error(
                "Debug data out of sync with function near: %s:%d. Try to recompile to fix this problem.",
                local_path,
                line_start,
            )
            return None

        logger.error(
            "Failed to find function symbol with filename and line: %s:%d. "
            + "If this issue persists after a recompile, the compiler has probably inlined this function.",
            local_path,
            line_start,
        )
        return None

    def find_line_of_recomp_address(self, address: int) -> tuple[PurePath, int] | None:
        if self._new_data:
            self._process()

        return self._address_to_path_and_line.get(address, None)
