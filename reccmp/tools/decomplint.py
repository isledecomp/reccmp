#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path, PurePath
from typing import Iterable
import colorama
import reccmp
import reccmp.color
from reccmp.dir import source_code_search
from reccmp.parser import DecompLinter
from reccmp.parser.error import ParserAlert
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging
from reccmp.project.detect import RecCmpProject
from reccmp.formats import TextFile

logger = logging.getLogger(__name__)

colorama.just_fix_windows_console()


def display_errors(alerts: Iterable[ParserAlert], filename: PurePath):
    sorted_alerts = sorted(alerts, key=lambda a: a.line_number)

    print(reccmp.color.Fore.LIGHTWHITE_EX, end="")
    print(filename)

    for alert in sorted_alerts:
        error_type = (
            f"{reccmp.color.Fore.RED}error: "
            if alert.is_error()
            else f"{reccmp.color.Fore.YELLOW}warning: "
        )
        components = [
            "  ",
            reccmp.color.Fore.LIGHTWHITE_EX,
            f"{alert.line_number:4}",
            " : ",
            " ",
            error_type,
            reccmp.color.Fore.LIGHTWHITE_EX,
            alert.code.name.lower(),
        ]
        print("".join(components), end="")

        if alert.line is not None:
            print(f"{reccmp.color.Fore.WHITE}  {alert.line}", end="")

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
    parser.add_argument(
        "--encoding",
        default="utf-8",
        type=str,
        help="The encoding of the checked files.",
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
    search_paths: list[Path] = []
    codefiles: list[TextFile] = []

    if not args.paths:
        # No path specified. Try to find the project file.
        project = RecCmpProject.from_directory(directory=Path.cwd())
        if not project:
            logger.error("Cannot find reccmp project")
            return 1

        # Read each target from the reccmp-project file
        # then get all filenames from each code directory.
        for target in project.targets.values():
            reduced_file_list = source_code_search(target.source_paths)
            codefiles.extend(
                TextFile.from_files(
                    reduced_file_list,
                    allow_error=True,
                    encoding=target.encoding or "utf-8",
                )
            )
    else:
        for path in args.paths:
            if path.is_dir() or path.is_file():
                search_paths.append(path)
            else:
                logger.error("Invalid path: %s", path)
        reduced_file_list = source_code_search(search_paths)
        codefiles = list(
            TextFile.from_files(
                reduced_file_list, allow_error=True, encoding=args.encoding
            )
        )

    warning_count, error_count = process_files(codefiles, module=args.module)

    print(colorama.Style.RESET_ALL, end="")

    would_fail = error_count > 0 or (warning_count > 0 and args.warnfail)
    if would_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
