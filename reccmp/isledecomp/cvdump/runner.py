import re
import io
from os import name as os_name
from enum import Enum
from typing import Iterable, Iterator
import subprocess
from reccmp.bin import lib_path_join
from reccmp.isledecomp.dir import winepath_unix_to_win
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
    def __init__(self, pdb: str) -> None:
        self._pdb: str = pdb
        self._options: set[DumpOpt] = set()

    def lines(self):
        self._options.add(DumpOpt.LINES)
        return self

    def symbols(self):
        self._options.add(DumpOpt.SYMBOLS)
        return self

    def globals(self):
        self._options.add(DumpOpt.GLOBALS)
        return self

    def publics(self):
        self._options.add(DumpOpt.PUBLICS)
        return self

    def section_contributions(self):
        self._options.add(DumpOpt.SECTION_CONTRIB)
        return self

    def modules(self):
        self._options.add(DumpOpt.MODULES)
        return self

    def types(self):
        self._options.add(DumpOpt.TYPES)
        return self

    def cmd_line(self) -> list[str]:
        cvdump_exe = lib_path_join("cvdump.exe")
        flags = [cvdump_opt_map[opt] for opt in self._options]

        if os_name == "nt":
            return [cvdump_exe, *flags, self._pdb]

        return ["wine", cvdump_exe, *flags, winepath_unix_to_win(self._pdb)]

    def run(self) -> CvdumpParser:
        parser = CvdumpParser()
        call = self.cmd_line()
        with subprocess.Popen(call, stdout=subprocess.PIPE) as proc:
            assert proc.stdout is not None
            wrap = io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="ignore")
            for name, section in iter_cvdump_sections(wrap):
                parser.read_section(name, section)

        return parser
