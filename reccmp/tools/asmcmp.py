#!/usr/bin/env python3

from collections.abc import Sequence
from datetime import datetime
import argparse
import logging
import os

import colorama
import reccmp
from reccmp.utils import (
    gen_svg,
    print_combined_diff,
    diff_json,
    percent_string,
    write_html_report,
)

from reccmp.compare import Compare
from reccmp.compare.diff import DiffReport, raw_diff_to_udiff
from reccmp.compare.report import (
    ReccmpStatusReport,
    ReccmpComparedEntity,
    deserialize_reccmp_report,
    serialize_reccmp_report,
    report_function_alignment,
    report_function_accuracy,
)
from reccmp.types import EntityType
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging
from reccmp.project.detect import (
    RecCmpProjectException,
    argparse_add_project_target_args,
    argparse_parse_project_target,
)

logger = logging.getLogger()
colorama.just_fix_windows_console()


def gen_json(json_file: str, json_str: str):
    """Convert the status report to JSON and write to a file."""

    with open(json_file, "w", encoding="utf-8") as f:
        f.write(json_str)


def print_match_verbose(
    match: DiffReport, show_both_addrs: bool = False, is_plain: bool = False
):
    percenttext = percent_string(
        match.effective_ratio, match.is_effective_match, is_plain
    )

    if show_both_addrs:
        addrs = f"0x{match.orig_addr:x} / 0x{match.recomp_addr:x}"
    else:
        addrs = hex(match.orig_addr)

    if match.is_stub:
        print(f"{addrs}: {match.name} is a stub. No diff.")
        return

    grouped_diff = match.match_type != EntityType.VTABLE
    udiff = raw_diff_to_udiff(match.result.diff, grouped=grouped_diff)

    if match.effective_ratio == 1.0:
        ok_text = (
            "OK!"
            if is_plain
            else (colorama.Fore.GREEN + "✨ OK! ✨" + colorama.Style.RESET_ALL)
        )
        if match.ratio == 1.0:
            print(f"{addrs}: {match.name} 100% match.\n\n{ok_text}\n\n")
        else:
            print_combined_diff(udiff, is_plain, show_both_addrs)

            print(
                f"\n{addrs}: {match.name} 100% effective match (differs, but only in ways that don't affect behavior).\n\n{ok_text}\n\n"
            )

    else:
        print_combined_diff(udiff, is_plain, show_both_addrs)

        print(
            f"\n{match.name} is only {percenttext} similar to the original, diff above"
        )


def print_match_oneline(
    match: ReccmpComparedEntity, show_both_addrs: bool = False, is_plain: bool = False
):
    percenttext = percent_string(
        match.effective_accuracy, match.is_effective_match, is_plain
    )

    if show_both_addrs:
        addrs = f"{match.orig_addr} / {match.recomp_addr}"
    else:
        addrs = match.orig_addr

    if match.is_stub:
        print(f"  {match.name} ({addrs}) is a stub.")
    else:
        print(f"  {match.name} ({addrs}) is {percenttext} similar to the original")


def parse_args() -> argparse.Namespace:
    def virtual_address(value) -> int:
        """Helper method for argparse, verbose parameter"""
        return int(value, 16)

    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Recompilation Compare: compare an original EXE with a recompiled EXE + PDB.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    argparse_add_project_target_args(parser)
    parser.add_argument(
        "--total",
        "-T",
        metavar="<count>",
        help="Total number of expected functions (improves total accuracy statistic)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        metavar="<offset>",
        type=virtual_address,
        help="Print assembly diff for specific function (original file's offset)",
    )
    parser.add_argument(
        "--json",
        metavar="<file>",
        help="Generate JSON file with match summary",
    )
    parser.add_argument(
        "--json-diet",
        action="store_true",
        help="Exclude diff from JSON report.",
    )
    parser.add_argument(
        "--diff",
        metavar="<file>",
        help="Diff against summary in JSON file",
    )
    parser.add_argument(
        "--dump",
        action="store_true",
        help="Write decompiled assembly to debug files.",
    )
    parser.add_argument(
        "--html",
        "-H",
        metavar="<file>",
        help="Generate searchable HTML summary of status and diffs",
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )
    parser.add_argument(
        "--svg", "-S", metavar="<file>", help="Generate SVG graphic of progress"
    )
    parser.add_argument("--svg-icon", metavar="icon", help="Icon to use in SVG (PNG)")
    parser.add_argument(
        "--print-rec-addr",
        action="store_true",
        help="Print addresses of recompiled functions too",
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Don't display text summary of matches",
    )
    parser.add_argument(
        "--nolib",
        action="store_true",
        help="Exclude LIBRARY annotations from the analysis",
    )
    argparse_add_logging_args(parser)

    args = parser.parse_args()
    argparse_parse_logging(args)

    return args


def dump_all_matched_functions(matches: Sequence[DiffReport]):
    logger.info("Creating assembly dump files.")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    orig_order = sorted(matches, key=lambda m: m.orig_addr)
    recomp_order = sorted(matches, key=lambda m: m.recomp_addr)

    with open(f"reccmp-{timestamp}-orig.txt", "w+", encoding="utf-8") as f:
        for match in orig_order:
            f.write(f"; {match.name}\n")
            for addr, line in match.result.diff.orig_inst:
                if addr:
                    f.write(f"{addr:10}: {line}\n")
                else:
                    f.write(f"        : {line}\n")

    with open(f"reccmp-{timestamp}-recomp.txt", "w+", encoding="utf-8") as f:
        for match in recomp_order:
            f.write(f"; {match.name}\n")
            for addr, line in match.result.diff.recomp_inst:
                if addr:
                    f.write(f"{addr:10}: {line}\n")
                else:
                    f.write(f"        : {line}\n")


def main():
    args = parse_args()

    try:
        target = argparse_parse_project_target(args)
    except RecCmpProjectException as e:
        logger.error("%s", e.args[0])
        return 1

    logging.basicConfig(level=args.loglevel, format="[%(levelname)s] %(message)s")

    compare = Compare.from_target(target)

    print()

    ### Compare one or none.

    if args.verbose is not None:
        match = compare.compare_address(args.verbose)
        if match is None:
            logger.error("Failed to find a match at address 0x%x", args.verbose)
            return 1

        print_match_verbose(
            match, show_both_addrs=args.print_rec_addr, is_plain=args.no_color
        )
        return 0

    ### Compare everything.

    compared = list(compare.compare_all())

    if args.dump:
        dump_all_matched_functions(compared)

    def should_include_match(match: DiffReport) -> bool:
        if (
            match.match_type == EntityType.FUNCTION
            and match.name in target.report_config.ignore_functions
        ):
            return False

        if args.nolib and match.is_library:
            return False

        return True

    report = ReccmpStatusReport(filename=target.original_path.name)

    # Build report:
    for match in compared:
        # if we are ignoring this function, skip to next one and don't add it to the entities list
        if not should_include_match(match):
            continue

        orig_addr = f"0x{match.orig_addr:x}"
        recomp_addr = f"0x{match.recomp_addr:x}"

        report.entities[orig_addr] = ReccmpComparedEntity(
            orig_addr=orig_addr,
            name=match.name,
            type=match.match_type,
            accuracy=match.effective_ratio,
            recomp_addr=recomp_addr,
            is_effective_match=match.is_effective_match,
            is_stub=match.is_stub,
            rdiff=match.result.diff,
        )

    # Count how many functions have the same virtual address in orig and recomp.
    functions_aligned_count = report_function_alignment(report)

    # Number of functions compared (i.e. excluding stubs)
    function_count, total_accuracy, total_effective_accuracy = report_function_accuracy(
        report
    )

    # Print diff summary to terminal
    if not args.silent and args.diff is None:
        for entity in report.entities.values():
            print_match_oneline(
                entity, show_both_addrs=args.print_rec_addr, is_plain=args.no_color
            )

    # Compare with saved diff report.
    if args.diff is not None:
        try:
            with open(args.diff, "r", encoding="utf-8") as f:
                saved_data = deserialize_reccmp_report(f.read())

            diff_json(
                saved_data,
                report,
                show_both_addrs=args.print_rec_addr,
                is_plain=args.no_color,
            )
        except FileNotFoundError:
            # In a CI workflow, the JSON file might not exist on the first run in a new branch.
            # Continue without a fatal error so users don't have to bother handling this situation.
            logger.error("Could not open JSON report file '%s' for diff", args.diff)

    ## Generate files and show summary.

    if args.json is not None:
        # If we're on a diet, hold the diff.
        diff_included = not bool(args.json_diet)
        gen_json(
            args.json, serialize_reccmp_report(report, diff_included=diff_included)
        )

    if args.html is not None:
        write_html_report(args.html, report)

    implemented_funcs = function_count

    # If we know how many functions are in the file (via analysis with Ghidra or other tools)
    # we can substitute an alternate value to use when calculating the percentages below.
    if args.total:
        # Use the alternate value if it exceeds the number of annotated functions
        function_count = max(function_count, int(args.total))

    if function_count > 0:
        effective_accuracy = total_effective_accuracy / function_count * 100
        actual_accuracy = total_accuracy / function_count * 100
        alignment_percentage = functions_aligned_count / function_count * 100
        print(
            f"\nTotal effective accuracy {effective_accuracy:.2f}% across {function_count} functions ({actual_accuracy:.2f}% actual accuracy)"
        )
        print(
            f"{functions_aligned_count} functions are aligned ({alignment_percentage:.2f}%)"
        )

        if args.svg is not None:
            gen_svg(
                args.svg,
                os.path.basename(target.original_path),
                args.svg_icon,
                implemented_funcs,
                function_count,
                total_effective_accuracy,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
