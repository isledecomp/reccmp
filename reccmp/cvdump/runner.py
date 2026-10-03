import re
import io
from os import name as os_name
from enum import Enum
from typing import Iterable, Iterator
import subprocess
from reccmp.bin import lib_path_join
from reccmp.dir import winepath_unix_to_win
from .cache import CvdumpCache
from .parser import CvdumpParser


class DumpOpt(Enum):
    LINES = 0
    SYMBOLS = 1
    GLOBALS = 2
    PUBLICS = 3
    SECTION_CONTRIB = 4
    MODULES = 5
    TYPES = 6


cvdump_opt_map = {
    DumpOpt.LINES: "-l",
    DumpOpt.SYMBOLS: "-s",
    DumpOpt.GLOBALS: "-g",
    DumpOpt.PUBLICS: "-p",
    DumpOpt.SECTION_CONTRIB: "-seccontrib",
    DumpOpt.MODULES: "-m",
    DumpOpt.TYPES: "-t",
}


def iter_cvdump_sections(stream: Iterable[str]) -> Iterator[tuple[str, str]]:
    r_section = re.compile(r"\*{3} ([A-Z]{2,}.+)\n")
    section = None
    lines = []

    for line in stream:
        if line[0] == "*" and (match := r_section.match(line)) is not None:
            if section is not None:
                yield (section, "".join(lines))
                lines.clear()

            section = match.group(1)
        else:
            lines.append(line)

    # Save the final section from stdout
    if section is not None:
        yield (section, "".join(lines))


class Cvdump:
    def __init__(
        self, pdb: str, *, cache: bool = False, invalidate_cache: bool = False
    ) -> None:
        self._pdb: str = pdb
        self.options: set[DumpOpt] = set()
        self._cache_enabled = cache
        self._invalidate_cache = invalidate_cache

    def lines(self):
        self.options.add(DumpOpt.LINES)
        return self

    def symbols(self):
        self.options.add(DumpOpt.SYMBOLS)
        return self

    def globals(self):
        self.options.add(DumpOpt.GLOBALS)
        return self

    def publics(self):
        self.options.add(DumpOpt.PUBLICS)
        return self

    def section_contributions(self):
        self.options.add(DumpOpt.SECTION_CONTRIB)
        return self

    def modules(self):
        self.options.add(DumpOpt.MODULES)
        return self

    def types(self):
        self.options.add(DumpOpt.TYPES)
        return self

    def flags(self) -> list[str]:
        return [cvdump_opt_map[opt] for opt in self.options if opt in cvdump_opt_map]

    def cache(self) -> CvdumpCache | None:
        """The cache entry for this PDB and this set of options, if enabled."""
        if not self._cache_enabled:
            return None

        return CvdumpCache(
            self._pdb,
            self.flags(),
            lib_path_join("cvdump.exe"),
            invalidate=self._invalidate_cache,
        )

    def cmd_line(self) -> list[str]:
        cvdump_exe = lib_path_join("cvdump.exe")
        flags = self.flags()

        if os_name == "nt":
            return [cvdump_exe, *flags, self._pdb]

        return ["wine", cvdump_exe, *flags, winepath_unix_to_win(self._pdb)]

    def _stream_from_cvdump(self, cache: CvdumpCache | None) -> Iterator[str]:
        """The output of cvdump.exe, saved to the cache on the way past if we
        have one. Writing while we parse keeps the subprocess and the parsing
        overlapped, so a cache miss costs no more than the disk write."""
        call = self.cmd_line()
        with subprocess.Popen(call, stdout=subprocess.PIPE) as proc:
            assert proc.stdout is not None
            wrap = io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="ignore")

            if cache is None:
                yield from wrap
                return

            with cache.writer() as write:
                for line in wrap:
                    write(line)
                    yield line

    def _stream(self) -> Iterator[str]:
        """The dump, from the cache if it holds one for these exact inputs."""
        cache = self.cache()
        if cache is not None:
            with cache.reader() as cached:
                if cached is not None:
                    yield from cached
                    return

        yield from self._stream_from_cvdump(cache)

    def run(self) -> CvdumpParser:
        parser = CvdumpParser()
        for name, section in iter_cvdump_sections(self._stream()):
            parser.read_section(name, section)

        return parser
