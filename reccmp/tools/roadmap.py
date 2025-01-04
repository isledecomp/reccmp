#!/usr/bin/env python

"""
For all addresses matched by code annotations or recomp pdb,
report how "far off" the recomp symbol is from its proper place
in the original binary.
"""

import os
import argparse
import logging
from pathlib import Path
import statistics
import bisect
from typing import Iterator, Tuple
from collections import namedtuple
import reccmp
from reccmp.isledecomp import PEImage, detect_image
from reccmp.isledecomp.compare.db import ReccmpEntity
from reccmp.isledecomp.cvdump import Cvdump
from reccmp.isledecomp.compare import Compare as IsleCompare
from reccmp.isledecomp.formats.exceptions import InvalidVirtualAddressError
from reccmp.isledecomp.types import SymbolType
from reccmp.project.detect import (
    argparse_add_built_project_target_args,
    argparse_parse_built_project_target,
)
from reccmp.project.error import RecCmpProjectException
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging

logger = logging.getLogger(__name__)


def or_blank(value) -> str:
    """Helper for dealing with potential None values in text output."""
    return "" if value is None else str(value)


class ModuleMap:
    """Load a subset of sections from the pdb to allow you to look up the
    module number based on the recomp address."""

    def __init__(self, pdb: Path, binfile: PEImage) -> None:
        cvdump = Cvdump(str(pdb)).section_contributions().modules().run()
        self.module_lookup: dict[int, tuple[str, str]] = {
            m.id: (m.lib, m.obj) for m in cvdump.modules
        }
        self.library_lookup = {m.obj: m.lib for m in cvdump.modules}
        self.section_contrib = [
            (
                binfile.get_abs_addr(sizeref.section, sizeref.offset),
                sizeref.size,
                sizeref.module,
            )
            for sizeref in cvdump.sizerefs
            if binfile.is_valid_section(sizeref.section)
        ]

        # For bisect performance enhancement
        self.contrib_starts = [start for (start, _, __) in self.section_contrib]

    def get_lib_for_module(self, module: str) -> str | None:
        return self.library_lookup.get(module)

    def get_all_cmake_modules(self) -> list[str]:
        return [
            obj
            for (_, (__, obj)) in self.module_lookup.items()
            if obj.startswith("CMakeFiles")
        ]

    def get_module(self, addr: int) -> str | None:
        i = bisect.bisect_left(self.contrib_starts, addr)
        # If the addr matches the section contribution start, we are in the
        # right spot. Otherwise, we need to subtract one here.
        # We don't want the insertion point given by bisect, but the
        # section contribution that contains the address.

        (potential_start, _, __) = self.section_contrib[i]
        if potential_start != addr:
            i -= 1

        # Safety catch: clamp to range of indices from section_contrib.
        i = max(0, min(i, len(self.section_contrib) - 1))

        (start, size, module_id) = self.section_contrib[i]
        if start <= addr < start + size:
            if (module := self.module_lookup.get(module_id)) is not None:
                return module

        return None


def print_sections(sections):
    print("    name |    start |   v.size | raw size")
    print("---------|----------|----------|----------")
    for sect in sections:
        name = sect.name
        print(
            f"{name:>8} | {sect.virtual_address:8x} | {sect.virtual_size:8x} | {sect.size_of_raw_data:8x}"
        )
    print()


ALLOWED_TYPE_ABBREVIATIONS = ["fun", "dat", "poi", "str", "vta", "flo"]


def match_type_abbreviation(mtype: int | None) -> str:
    """Return abbreviation of the given SymbolType name"""
    if mtype is None:
        return ""

    return SymbolType(mtype).name.lower()[:3]


def get_cmakefiles_prefix(module: str) -> str:
    """For the given .obj, get the "CMakeFiles/something.dir/" prefix.
    For lack of a better option, this is the library for this module."""
    if module.startswith("CMakeFiles"):
        return "/".join(module.split("/", 2)[:2]) + "/"

    return module


def truncate_module_name(prefix: str, module: str) -> str:
    """Remove the CMakeFiles prefix and the .obj suffix for the given module.
    Input: CMakeFiles/lego1.dir/, CMakeFiles/lego1.dir/LEGO1/define.cpp.obj
    Output: LEGO1/define.cpp"""

    if module.startswith(prefix):
        module = module[len(prefix) :]

    if module.endswith(".obj"):
        module = module[:-4]

    return module


def avg_remove_outliers(entries: list[int]) -> int:
    """Compute the average from this list of entries (addresses)
    after removing outlier values."""

    if len(entries) == 1:
        return entries[0]

    avg = statistics.mean(entries)
    sd = statistics.pstdev(entries)

    return int(statistics.mean([e for e in entries if abs(e - avg) <= 2 * sd]))


RoadmapRow = namedtuple(
    "RoadmapRow",
    [
        "orig_sect_ofs",
        "recomp_sect_ofs",
        "orig_addr",
        "recomp_addr",
        "displacement",
        "sym_type",
        "size",
        "name",
        "module",
    ],
)


class DeltaCollector:
    """Reads each row of the results and aggregates information about the
    placement of each module."""

    def __init__(self, match_type: str = "fun") -> None:
        # The displacement for each symbol from each module
        self.disp_map = {}

        # Each address for each module
        self.addresses = {}

        # The earliest address for each module
        self.earliest = {}

        # String abbreviation for which symbol type we are checking
        self.match_type = "fun"

        match_type = str(match_type).strip().lower()[:3]
        if match_type in ALLOWED_TYPE_ABBREVIATIONS:
            self.match_type = match_type

    def read_row(self, row: RoadmapRow):
        if row.module is None:
            return

        if row.sym_type != self.match_type:
            return

        if row.orig_addr is not None:
            if row.module not in self.addresses:
                self.addresses[row.module] = []

            self.addresses[row.module].append(row.orig_addr)

            if row.orig_addr < self.earliest.get(row.module, 0xFFFFFFFFF):
                self.earliest[row.module] = row.orig_addr

        if row.displacement is not None:
            if row.module not in self.disp_map:
                self.disp_map[row.module] = []

            self.disp_map[row.module].append(row.displacement)

    def iter_sorted(self) -> Iterator[Tuple[int, int]]:
        """Compute the average address for each module, then generate them
        in ascending order."""
        avg_address = {
            mod: avg_remove_outliers(values) for mod, values in self.addresses.items()
        }
        for mod, avg in sorted(avg_address.items(), key=lambda x: x[1]):
            yield (avg, mod)


def suggest_order(results: list[RoadmapRow], module_map: ModuleMap, match_type: str):
    """Suggest the order of modules for CMakeLists.txt"""

    dc = DeltaCollector(match_type)
    for row in results:
        dc.read_row(row)

    # First, show the order of .obj files for the "CMake Modules"
    # Meaning: the modules where the .obj file begins with "CMakeFiles".
    # These are the libraries where we directly control the order.
    # The library name (from cvdump) doesn't make it obvious that these are
    # our libraries so we derive the name based on the CMakeFiles prefix.
    leftover_modules = set(module_map.get_all_cmake_modules())

    # A little convoluted, but we want to take the first two tokens
    # of the string with '/' as the delimiter.
    # i.e. CMakeFiles/isle.dir/
    # The idea is to print exactly what appears in CMakeLists.txt.
    cmake_prefixes = sorted(set(get_cmakefiles_prefix(mod) for mod in leftover_modules))

    # Save this off because we'll use it again later.
    computed_order = list(dc.iter_sorted())

    for prefix in cmake_prefixes:
        print(prefix)

        last_earliest = 0
        # Show modules ordered by the computed average of addresses
        for _, module in computed_order:
            if not module.startswith(prefix):
                continue

            leftover_modules.remove(module)

            avg_displacement = None
            displacements = dc.disp_map.get(module)
            if displacements is not None and len(displacements) > 0:
                avg_displacement = int(statistics.mean(displacements))

            # Call attention to any modules where ordering by earliest
            # address is different from the computed order we display.
            earliest = dc.earliest.get(module)
            ooo_mark = "*" if earliest < last_earliest else " "
            last_earliest = earliest

            code_file = truncate_module_name(prefix, module)
            print(f"0x{earliest:08x}{ooo_mark} {avg_displacement:10}  {code_file}")

        # These modules are included in the final binary (in some form) but
        # don't contribute any symbols of the type we are checking.
        # n.b. There could still be other modules that are part of
        # CMakeLists.txt but are not included in the pdb for whatever reason.
        # In other words: don't take the list we provide as the final word on
        # what should or should not be included.
        # This is merely a suggestion of the order.
        for module in leftover_modules:
            if not module.startswith(prefix):
                continue

            # aligned with previous print
            code_file = truncate_module_name(prefix, module)
            print(f"      no suggestion     {code_file}")

        print()

    # Now display the order of all libaries in the final file.
    library_order = {}

    for start, module in computed_order:
        lib = module_map.get_lib_for_module(module)
        if lib is None:
            lib = get_cmakefiles_prefix(module)

        if start < library_order.get(lib, 0xFFFFFFFFF):
            library_order[lib] = start

    print("Library order (average address shown):")
    for lib, start in sorted(library_order.items(), key=lambda x: x[1]):
        # Strip off any OS path for brevity
        if not lib.startswith("CMakeFiles"):
            lib = os.path.basename(lib)

        print(f"{lib:40} {start:08x}")


def print_text_report(results: list[RoadmapRow]):
    """Print the result with original and recomp addresses."""
    for row in results:
        print(
            "  ".join(
                [
                    f"{or_blank(row.orig_sect_ofs):14}",
                    f"{or_blank(row.recomp_sect_ofs):14}",
                    f"{or_blank(row.displacement):>8}",
                    f"{row.sym_type:3}",
                    f"{or_blank(row.size):6}",
                    or_blank(row.name),
                ]
            )
        )


def print_diff_report(results: list[RoadmapRow]):
    """Print only entries where we have the recomp address.
    This is intended for generating a file to diff against.
    The recomp addresses are always changing so we hide those."""
    for row in results:
        if row.orig_addr is None or row.recomp_addr is None:
            continue

        print(
            "  ".join(
                [
                    f"{or_blank(row.orig_sect_ofs):14}",
                    f"{or_blank(row.displacement):>8}",
                    f"{row.sym_type:3}",
                    f"{or_blank(row.size):6}",
                    or_blank(row.name),
                ]
            )
        )


def export_to_csv(csv_file: str, results: list[RoadmapRow]):
    with open(csv_file, "w+", encoding="utf-8") as f:
        f.write(
            "orig_sect_ofs,recomp_sect_ofs,orig_addr,recomp_addr,displacement,row_type,size,name,module\n"
        )
        for row in results:
            f.write(",".join(map(or_blank, row)))
            f.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Recompilation Compare: compare an original EXE with a recompiled EXE + PDB.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    argparse_add_built_project_target_args(parser)

    parser.add_argument("--csv", metavar="<file>", help="If set, export to CSV")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show recomp addresses in output"
    )
    parser.add_argument(
        "--order",
        const="fun",
        nargs="?",
        type=str,
        help="Show suggested order of modules (using the specified symbol type)",
    )

    argparse_add_logging_args(parser)
    args = parser.parse_args()
    argparse_parse_logging(args=args)
    if args.loglevel != logging.DEBUG:
        # Mute logger events from compare engine
        logging.getLogger("isledecomp.compare.core").setLevel(logging.CRITICAL)
        logging.getLogger("isledecomp.compare.db").setLevel(logging.CRITICAL)
        logging.getLogger("isledecomp.compare.lines").setLevel(logging.CRITICAL)

    return args


def main() -> int:
    args = parse_args()

    try:
        target = argparse_parse_built_project_target(args=args)
    except RecCmpProjectException as e:
        logger.error(e.args[0])
        return 1

    orig_bin = detect_image(target.original_path)
    assert isinstance(orig_bin, PEImage)

    recomp_bin = detect_image(target.recompiled_path)
    assert isinstance(recomp_bin, PEImage)

    engine = IsleCompare(
        orig_bin,
        recomp_bin,
        target.recompiled_pdb,
        target.source_root,
        target_id=target.target_id,
    )

    module_map = ModuleMap(target.recompiled_pdb, recomp_bin)

    def is_same_section(orig: int, recomp: int) -> bool:
        """Compare the section name instead of the index.
        LEGO1.dll adds extra sections for some reason. (Smacker library?)"""

        try:
            orig_name = orig_bin.sections[orig - 1].name
            recomp_name = recomp_bin.sections[recomp - 1].name
            return orig_name == recomp_name
        except IndexError:
            return False

    def to_roadmap_row(match: ReccmpEntity):
        orig_sect = None
        orig_ofs = None
        orig_sect_ofs = None
        recomp_sect = None
        recomp_ofs = None
        recomp_sect_ofs = None
        orig_addr = None
        recomp_addr = None
        displacement = None
        module_name = None

        if match.recomp_addr is not None and recomp_bin.is_valid_vaddr(
            match.recomp_addr
        ):
            if (module_ref := module_map.get_module(match.recomp_addr)) is not None:
                (_, module_name) = module_ref

        row_type = match_type_abbreviation(match.compare_type)
        name = (
            repr(match.name) if match.compare_type == SymbolType.STRING else match.name
        )

        if match.orig_addr is not None:
            orig_addr = match.orig_addr
            (orig_sect, orig_ofs) = orig_bin.get_relative_addr(match.orig_addr)
            orig_sect_ofs = f"{orig_sect:04}:{orig_ofs:08x}"

        if match.recomp_addr is not None:
            recomp_addr = match.recomp_addr
            (recomp_sect, recomp_ofs) = recomp_bin.get_relative_addr(match.recomp_addr)
            recomp_sect_ofs = f"{recomp_sect:04}:{recomp_ofs:08x}"

        if (
            orig_sect is not None
            and recomp_sect is not None
            and is_same_section(orig_sect, recomp_sect)
        ):
            assert recomp_ofs is not None
            assert orig_ofs is not None
            displacement = recomp_ofs - orig_ofs

        return RoadmapRow(
            orig_sect_ofs,
            recomp_sect_ofs,
            orig_addr,
            recomp_addr,
            displacement,
            row_type,
            match.size,
            name,
            module_name,
        )

    def roadmap_row_generator(matches):
        for match in matches:
            try:
                yield to_roadmap_row(match)
            except InvalidVirtualAddressError:
                # This is here to work around the fact that we have RVA
                # values (i.e. not real virtual addrs) in our compare db.
                pass

    results = list(roadmap_row_generator(engine.get_all()))

    if args.order is not None:
        suggest_order(results, module_map, args.order)
        return 0

    if args.csv is None:
        if args.verbose:
            print("ORIG sections:")
            print_sections(orig_bin.sections)

            print("RECOMP sections:")
            print_sections(recomp_bin.sections)

            print_text_report(results)
        else:
            print_diff_report(results)

    if args.csv is not None:
        export_to_csv(args.csv, results)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
