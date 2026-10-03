"""Optional on-disk cache for the text that cvdump.exe produces.

Dumping the debug information of a large PDB takes a few seconds, and the text
is a pure function of the PDB and the options we ask for. A workflow that runs
reccmp several times against one build therefore pays for the same dump over
and over. Keeping the text lets those later runs skip the subprocess and parse
the saved copy instead.

The cache is off unless the caller asks for it, because a cache that serves a
stale dump reports a comparison against a binary that no longer exists, which
is worse than being slow. An entry is used only when the PDB has the same size
and modification time as when it was written, and when the options and the
cvdump.exe we would call are unchanged.
"""

import hashlib
import json
import logging
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, IO, Iterator, Sequence

logger = logging.getLogger(__name__)

# Bump when the meaning of the metadata or the layout of the file changes, so
# that entries written by an older reccmp are ignored instead of misread.
CACHE_FORMAT = 1


def cache_directory() -> Path:
    """Where to keep cached dumps. RECCMP_CACHE_DIR overrides the default."""
    override = os.environ.get("RECCMP_CACHE_DIR")
    if override:
        return Path(override)

    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "reccmp" / "Cache"
    else:
        base = os.environ.get("XDG_CACHE_HOME")
        if base:
            return Path(base) / "reccmp"

        home = os.path.expanduser("~")
        if home != "~":
            return Path(home) / ".cache" / "reccmp"

    return Path(tempfile.gettempdir()) / "reccmp-cache"


def _file_signature(path: Path) -> list[int] | None:
    """Size and modification time, or None if we cannot read them.

    A list rather than a tuple because this goes through JSON, which has one
    array type: a tuple would come back as a list and never compare equal to
    the metadata we build for the current inputs.
    """
    try:
        st = path.stat()
    except OSError:
        return None

    return [st.st_size, st.st_mtime_ns]


class CvdumpCache:
    """The cached dump for one PDB and one set of cvdump options."""

    def __init__(
        self,
        pdb: str | Path,
        flags: Sequence[str],
        executable: str | Path,
        *,
        invalidate: bool = False,
    ) -> None:
        self._pdb = Path(pdb)
        self._flags = sorted(flags)
        self._executable = Path(executable)
        self._invalidate = invalidate

    def _metadata(self) -> dict | None:
        """What a valid entry for the current inputs must say about itself."""
        pdb = _file_signature(self._pdb)
        if pdb is None:
            return None

        return {
            "format": CACHE_FORMAT,
            "pdb": str(self._pdb.resolve()),
            "pdb_size": pdb[0],
            "pdb_mtime_ns": pdb[1],
            "flags": self._flags,
            "cvdump": _file_signature(self._executable),
        }

    def _path(self) -> Path:
        """One file per PDB and option set, so a rebuild replaces its own entry
        instead of adding another."""
        digest = hashlib.sha256(
            "\0".join([str(self._pdb.resolve()), *self._flags]).encode("utf-8")
        ).hexdigest()[:32]
        return cache_directory() / (digest + ".cvdump")

    @contextmanager
    def reader(self) -> Iterator[IO[str] | None]:
        """The cached text for these inputs, or None if there is nothing usable."""
        if self._invalidate:
            yield None
            return

        wanted = self._metadata()
        if wanted is None:
            yield None
            return

        path = self._path()
        try:
            # The metadata is the first line, the dump is the rest.
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                header = handle.readline()
                try:
                    found = json.loads(header)
                except ValueError:
                    found = None

                # A cvdump signature of None means we could not stat the
                # executable, which we cannot treat as a match.
                if found != wanted or wanted["cvdump"] is None:
                    logger.debug("Cached dump %s does not match the inputs", path)
                    yield None
                    return

                logger.info("Using the cached dump of %s", self._pdb)
                yield handle
        except OSError:
            yield None

    @contextmanager
    def writer(self) -> Iterator[Callable[[str], object]]:
        """Collect the dump as it streams past, and keep it only if we reach the
        end of the stream without an error. A partial dump must never be stored:
        it would parse as a complete one."""
        metadata = self._metadata()
        if metadata is None:
            yield lambda _: None
            return

        directory = cache_directory()
        try:
            directory.mkdir(parents=True, exist_ok=True)
            # Write beside the destination so the replace below stays on one
            # filesystem, and so a crash cannot leave a half-written entry in
            # the cache under its real name.
            handle = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=directory,
                prefix="partial-",
                suffix=".cvdump",
                delete=False,
            )
        except OSError as ex:
            logger.warning("Cannot write to the cache directory %s: %s", directory, ex)
            yield lambda _: None
            return

        temporary = Path(handle.name)
        try:
            with handle:
                handle.write(json.dumps(metadata, sort_keys=True) + "\n")
                yield handle.write

            os.replace(temporary, self._path())
            logger.debug("Cached the dump of %s", self._pdb)
        except BaseException:
            # Includes GeneratorExit, i.e. a consumer that stopped reading.
            temporary.unlink(missing_ok=True)
            raise
