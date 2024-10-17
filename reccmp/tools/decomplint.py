#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path
import colorama
import reccmp
from reccmp.isledecomp.dir import walk_source_dir, is_file_cpp
from reccmp.isledecomp.parser import DecompLinter
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging
from reccmp.project.detect import RecCmpProject

logger = logging.getLogger(__name__)

colorama.just_fix_windows_console()


def display_errors(alerts, filename):
    sorted_alerts = sorted(alerts, key=lambda a: a.line_number)

    for alert in sorted_alerts:
        error_type = (
            f"{colorama.Fore.RED}error: "
            if alert.is_error()
            else f"{colorama.Fore.YELLOW}warning: "
        )
        components = [
            colorama.Fore.LIGHTWHITE_EX,
            filename,
            ":",
            str(alert.line_number),
            " : ",
            error_type,
            colorama.Fore.LIGHTWHITE_EX,
            alert.code.name.lower(),
        ]
        print("".join(components))

        if alert.line is not None:
            print(f"{colorama.Fore.WHITE}  {alert.line}")


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


def process_files(files, module=None):
    warning_count = 0
    error_count = 0

    linter = DecompLinter()
    for filename in files:
        success = linter.check_file(filename, module)

        warnings = [a for a in linter.alerts if a.is_warning()]
        errors = [a for a in linter.alerts if a.is_error()]

        error_count += len(errors)
        warning_count += len(warnings)

        if not success:
            display_errors(linter.alerts, filename)
            print()

    return (warning_count, error_count)


def main():
    args = parse_args()

    if not args.paths:
        project = RecCmpProject.from_directory(directory=Path.cwd())
        if not project:
            logger.error("Cannot find reccmp project")
            return 1
        print(project.targets)
        args.paths = list(target.source_root for target in project.targets.values())

    files_to_check = []
    for path in args.paths:
        if path.is_dir():
            files_to_check.extend(walk_source_dir(path))
        elif path.is_file() and is_file_cpp(path):
            files_to_check.append(path)
        else:
            logger.error("Invalid path: %s", path)

    (warning_count, error_count) = process_files(files_to_check, module=args.module)

    print(colorama.Style.RESET_ALL, end="")

    would_fail = error_count > 0 or (warning_count > 0 and args.warnfail)
    if would_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
