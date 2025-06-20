"""Utility functions and modules for path resolution and traversal"""

import os
import subprocess
from typing import Iterator
from pathlib import Path, PurePath, PureWindowsPath


def winepath_win_to_unix(path: str) -> str:
    return subprocess.check_output(["winepath", path], text=True).strip()


def winepath_unix_to_win(path: str) -> str:
    return subprocess.check_output(["winepath", "-w", path], text=True).strip()


def _iter_path_components(path: PurePath) -> Iterator[str]:
    """Walk path components in reverse and convert to lower case for matching."""
    for p in reversed(path.parts):
        yield p.lower()


def _count_matching_path_parts(
    foreign_path: PurePath, local_path: PurePath
) -> tuple[int, PurePath]:
    score = 0
    for fp, lp in zip(
        _iter_path_components(foreign_path), _iter_path_components(local_path)
    ):
        # Don't try to resolve any dot directories.
        # We would get it wrong if any of the paths are symlinks.
        if fp != lp or fp in (".", "..") or lp in (".", ".."):
            break

        score += 1

    return (score, local_path)


def convert_foreign_path(
    foreign_path: PurePath, local_paths: tuple[PurePath]
) -> PurePath | None:
    """Connect the given foreign_path to the best match from the list of local_paths.
    For best performance, you should narrow down the starting list to paths
    that match the base filename."""
    scored = [_count_matching_path_parts(foreign_path, p) for p in local_paths]
    scored.sort(reverse=True)

    if len(scored) >= 2:
        [(top_score, top_path), (next_score, _)] = scored[:2]
        # Return if this is the best match above all others
        if top_score > next_score:
            return top_path

        # If there are two or more paths with an equal number of
        # matching parts, none are clearly correct, so we return None.
        return None

    if len(scored) == 1:
        (top_score, top_path) = scored[0]
        # Return only if we matched at least one part
        if top_score > 0:
            return top_path

        return None

    return None


class PathResolver:
    """Intended to resolve Windows/Wine paths used in the PDB (cvdump) output
    into a "canonical" format to be matched against code file paths from os.walk.
    MSVC may include files from the parent dir using `..`. We eliminate those and create
    an absolute path so that information about the same file under different names
    will be combined into the same record. (i.e. line_no/addr pairs from LINES section.)
    """

    def __init__(self, basedir) -> None:
        """basedir is the root path of the code directory in the format for your OS.
        We will convert it to a PureWindowsPath to be platform-independent
        and match that to the paths from the PDB."""

        # Memoize the converted paths. We will need to do this for each path
        # in the PDB, for each function in that file. (i.e. lots of repeated work)
        self._memo: dict[str, str] = {}

        # Convert basedir to an absolute path if it is not already.
        # If it is not absolute, we cannot do the path swap on unix.
        self._realdir = Path(basedir).resolve()

        self._is_unix = os.name != "nt"
        if self._is_unix:
            self._basedir: PurePath = PureWindowsPath(
                winepath_unix_to_win(str(self._realdir))
            )
        else:
            self._basedir = self._realdir

    def _memo_wrapper(self, path_str: str) -> str:
        """Wrapper so we can memoize from the public caller method"""
        path: PurePath = PureWindowsPath(path_str)
        if not path.is_absolute():
            # pathlib syntactic sugar for path concat
            path = self._basedir / path

        if self._is_unix:
            # If the given path is relative to the basedir, deconstruct the path
            # and swap in our unix path to avoid an expensive call to winepath.
            try:
                # Will raise ValueError if we are not relative to the base.
                section = path.relative_to(self._basedir)
                # Should combine to pathlib.PosixPath
                mockpath = (self._realdir / section).resolve()
                if mockpath.is_file():
                    return str(mockpath)
            except ValueError:
                pass

            # We are not relative to the basedir, or our path swap attempt
            # did not point at an actual file. Either way, we are forced
            # to call winepath using our original path.
            return winepath_win_to_unix(str(path))

        # We must be on Windows. Convert back to WindowsPath.
        # The resolve() call will eliminate intermediate backdir references.
        return str(Path(path).resolve())

    def resolve_cvdump(self, path_str: str) -> str:
        """path_str is in Windows/Wine path format.
        We will return a path in the format for the host OS."""
        if path_str not in self._memo:
            self._memo[path_str] = self._memo_wrapper(path_str)

        return self._memo[path_str]


def is_file_c_like(filename: Path | str) -> bool:
    return Path(filename).suffix.lower() in (
        ".c",
        ".h",
        ".cc",
        ".hh",
        ".cxx",
        ".hxx",
        ".cpp",
        ".hpp",
        ".C",
    )


def walk_source_dir(source: Path, recursive: bool = True) -> Iterator[str]:
    """Generator to walk the given directory recursively and return
    any C++ files found."""

    for subdir, _, files in os.walk(source.absolute()):
        for file in files:
            if is_file_c_like(file):
                yield os.path.join(subdir, file)

        if not recursive:
            break
