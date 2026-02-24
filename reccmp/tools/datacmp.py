# (New) Data comparison.

import os
import argparse
import logging
from typing import Iterator
import colorama
import reccmp
from reccmp.compare import Compare
from reccmp.compare.variables import (
    ComparedOffset,
    CompareResult,
    ComparisonItem,
    VariableComparator,
)
from reccmp.formats.pe import PEImage
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging
from reccmp.project.detect import (
    RecCmpProjectException,
    RecCmpTarget,
    argparse_add_project_target_args,
    argparse_parse_project_target,
)


logger = logging.getLogger(__name__)

colorama.just_fix_windows_console()


# Ignore all compare-db messages.
logging.getLogger("compare").addHandler(logging.NullHandler())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Comparing data values.")
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    argparse_add_project_target_args(parser)
    parser.add_argument(
        "-v",
        "--verbose",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="",
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )
    parser.add_argument(
        "--all",
        "-a",
        dest="show_all",
        action="store_true",
        help="Only show variables with a problem",
    )
    parser.add_argument(
        "--print-rec-addr",
        action="store_true",
        help="Print addresses of recompiled functions too",
    )
    argparse_add_logging_args(parser)

    args = parser.parse_args()

    argparse_parse_logging(args)
    return args


def do_the_comparison(target: RecCmpTarget) -> Iterator[ComparisonItem]:
    """Run through each variable in our compare DB, then do the comparison
    according to the variable's type. Emit the result."""
    compare = Compare.from_target(target)
    origfile = compare.orig_bin
    recompfile = compare.recomp_bin

    if not isinstance(origfile, PEImage) or not isinstance(recompfile, PEImage):
        raise ValueError("`datacmp` currently only supports 32-bit PE images")

    variable_comparator = VariableComparator(
        # pylint: disable=protected-access
        db=compare._db,
        types=compare.types,
        orig_bin=origfile,
        recomp_bin=recompfile,
    )

    for var in compare.get_variables():
        yield variable_comparator.compare_variable(var)


def colorize_match_result(result: CompareResult, no_color: bool) -> str:
    """Helper to return color string or not, depending on user preference"""
    if no_color:
        return result.name

    match result:
        case CompareResult.MATCH:
            color = colorama.Fore.GREEN
        case CompareResult.ERROR | CompareResult.DIFF:
            color = colorama.Fore.RED
        case _:
            color = colorama.Fore.YELLOW

    return f"{color}{result.name}{colorama.Style.RESET_ALL}"


def compared_offset_string(c: ComparedOffset, no_color: bool) -> str:
    """Display the offset, name, and value diff for each compared item.
    Scalar variables have only a single item, the value itself."""

    def ansi_wrap(c: str):
        """Easily remove the ANSI codes in --no-color mode."""
        return "" if no_color else c

    offset = f"+ 0x{c.offset:02x}"
    header_chunk = [ansi_wrap(colorama.Fore.LIGHTBLACK_EX), f"{offset:>10}"]

    name_chunk = [
        ": " if c.name else "  ",
        ansi_wrap(colorama.Fore.WHITE),
        f"{c.name if c.name else '':30}",
    ]

    (value_a, value_b) = c.values
    values_chunk = [ansi_wrap(colorama.Fore.LIGHTWHITE_EX), value_a]
    if not c.match:
        values_chunk.extend([" : ", ansi_wrap(colorama.Fore.LIGHTBLACK_EX), value_b])

    return " ".join(
        [
            "".join(header_chunk),
            "".join(name_chunk),
            "".join(values_chunk),
            ansi_wrap(colorama.Style.RESET_ALL),
        ]
    )


def main():
    args = parse_args()

    try:
        target = argparse_parse_project_target(args=args)
    except RecCmpProjectException as e:
        logger.error(e.args[0])
        return 1

    var_count = 0
    problems = 0

    for item in do_the_comparison(target):
        var_count += 1
        if item.result in (CompareResult.DIFF, CompareResult.ERROR):
            problems += 1

        if not args.show_all and item.result == CompareResult.MATCH:
            continue

        address_display = (
            f"0x{item.orig_addr:x} / 0x{item.recomp_addr:x}"
            if args.print_rec_addr
            else f"0x{item.orig_addr:x}"
        )

        print(
            f"{item.name[:80]} ({address_display}) ... {colorize_match_result(item.result, args.no_color)} "
        )
        if item.error is not None:
            print(f"  {item.error}")

        if item.raw_only:
            print("  Unknown or unsupported data type, comparing raw data only.")

        for c in item.compared:
            if not args.verbose and c.match:
                continue

            print(compared_offset_string(c, args.no_color))

        if args.verbose:
            print()

    print(
        f"{os.path.basename(target.original_path)} - Variables: {var_count}. Issues: {problems}"
    )
    return 0 if problems == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
