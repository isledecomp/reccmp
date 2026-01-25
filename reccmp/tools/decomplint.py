#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path, PurePath
from typing import Iterable
import colorama
import reccmp
from reccmp.dir import walk_source_dir
from reccmp.parser import DecompLinter
from reccmp.parser.error import ParserAlert
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging
from reccmp.project.detect import RecCmpProject
from reccmp.formats import TextFile

logger = logging.getLogger(__name__)

colorama.just_fix_windows_console()


def display_errors(alerts: Iterable[ParserAlert], filename: PurePath):
    sorted_alerts = sorted(alerts, key=lambda a: a.line_number)

    print(colorama.Fore.LIGHTWHITE_EX, end="")
    print(filename)

    for alert in sorted_alerts:
        error_type = (
            f"{colorama.Fore.RED}error: "
            if alert.is_error()
            else f"{colorama.Fore.YELLOW}warning: "
        )
        components = [
            "  ",
            colorama.Fore.LIGHTWHITE_EX,
            f"{alert.line_number:4}",
            " : ",
            " ",
            error_type,
            colorama.Fore.LIGHTWHITE_EX,
            alert.code.name.lower(),
        ]
        print("".join(components), end="")

        if alert.line is not None:
            print(f"{colorama.Fore.WHITE}  {alert.line}", end="")

        print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Syntax checking and linting for decomp annotation markers."
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    parser.add_argument(
        "paths",
        metavar="<path>",
        nargs="*",
        type=Path,
        help="The file or directory to check.",
    )
    parser.add_argument(
        "--module",
        required=False,
        type=str,
        help="If present, run targeted checks for markers from the given module.",
    )
    parser.add_argument(
        "--warnfail",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail if syntax warnings are found.",
    )
    argparse_add_logging_args(parser)

    args = parser.parse_args()

    argparse_parse_logging(args)

    return args


def process_files(
    files: Iterable[TextFile], module: str | None = None
) -> tuple[int, int]:
    warning_count = 0
    error_count = 0

    linter = DecompLinter()
    for file in files:
        success = linter.read(file.text, file.path, module)

        warnings = [a for a in linter.alerts if a.is_warning()]
        errors = [a for a in linter.alerts if a.is_error()]

        error_count += len(errors)
        warning_count += len(warnings)

        if not success:
            display_errors(linter.alerts, file.path)
            print()

    return (warning_count, error_count)


def main():
    args = parse_args()
    files_to_check: list[Path] = []

    if not args.paths:
        # No path specified. Try to find the project file.
        project = RecCmpProject.from_directory(directory=Path.cwd())
        if not project:
            logger.error("Cannot find reccmp project")
            return 1

        # Read each target from the reccmp-project file
        # then get all filenames from each code directory.
        for target in project.targets.values():
            if target.source_root:
                files_to_check.extend(walk_source_dir(target.source_root))
    else:
        for path in args.paths:
            if path.is_dir():
                files_to_check.extend(walk_source_dir(path))
            elif path.is_file():
                files_to_check.append(path)
            else:
                logger.error("Invalid path: %s", path)

    # Use set() so we check each file only once.
    reduced_file_list = sorted(set(files_to_check))

    codefiles = list(TextFile.from_files(reduced_file_list, allow_error=True))

    (warning_count, error_count) = process_files(codefiles, module=args.module)

    print(colorama.Style.RESET_ALL, end="")

    would_fail = error_count > 0 or (warning_count > 0 and args.warnfail)
    if would_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
