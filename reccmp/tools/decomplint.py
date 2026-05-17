#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path, PurePath
from typing import Iterable
import colorama
import reccmp
import reccmp.color
from reccmp.dir import source_code_search
from reccmp.parser import DecompParser, ReccmpParserResult
from reccmp.parser.linter import (
    check_byname_allowed,
    check_function_order,
    lint_file_collections,
)
from reccmp.parser.error import AlertCode, ParserAlert
from reccmp.project.common import RECCMP_BUILD_CONFIG, RECCMP_PROJECT_CONFIG
from reccmp.project.error import (
    RecCmpProjectException,
    RecCmpProjectNotFoundException,
)
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging
from reccmp.project.detect import RecCmpProject
from reccmp.formats import TextFile

logger = logging.getLogger(__name__)

colorama.just_fix_windows_console()


def display_errors(alerts: Iterable[ParserAlert], filename: Path | PurePath):
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
            f"[{alert.target}] " if alert.target else "",
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
    # Combine --target and --module because they have the same goal:
    # focusing on specific annotations to run order and uniqueness checks.
    # If specific paths are provided, target defines which annotations to verify.
    # If no paths are provided, use the path list for that target in the reccmp project.
    parser.add_argument(
        "--target",
        "--module",
        metavar="<target-id>",
        help="Run checks on annotations for the given target only.",
    )
    parser.add_argument(
        "paths",
        metavar="<paths>",
        nargs="*",
        type=Path,
        help="The files or directories to check.",
    )
    parser.add_argument(
        "--warnfail",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail if syntax warnings are found.",
    )
    parser.add_argument(
        "--encoding",
        type=str,
        help="The encoding of the checked files.",
    )
    argparse_add_logging_args(parser)

    args = parser.parse_args()

    argparse_parse_logging(args)

    return args


class DecomplintOptions:
    paths: tuple[Path, ...]
    module: str | None
    encoding: str

    def __init__(
        self, paths: tuple[Path, ...], module: str | None, encoding: str | None
    ):
        self.paths = paths
        self.module = module
        self.encoding = encoding or "utf-8"


def decomplint_parse_args(
    args: argparse.Namespace,
) -> tuple[DecomplintOptions, ...]:
    """Produce a list of scopes and files to check from the command-line args:
    1. No arguments: Lint each target separately
    2. Target: Lint its files only
    3. List of paths: Lint these files (with optional target scope)
    """
    if args.paths:
        paths = tuple(source_code_search(args.paths))
        module = args.target
        encoding = args.encoding

        return (DecomplintOptions(paths, module, encoding),)

    project = RecCmpProject.from_directory(Path.cwd())
    if not project:
        raise RecCmpProjectNotFoundException(
            f"Cannot find a reccmp project (missing {RECCMP_PROJECT_CONFIG}/{RECCMP_BUILD_CONFIG})"
        )

    options = []

    for target in project.targets.values():
        if args.target and target.target_id != args.target:
            continue

        paths = tuple(source_code_search(target.source_paths))
        module = target.target_id
        encoding = args.encoding if args.encoding else target.encoding

        options.append(DecomplintOptions(paths, module, encoding))

    return tuple(options)


def parse_file(file: TextFile) -> ReccmpParserResult:
    parser = DecompParser()
    parser.reset_and_set_filename(file.path)
    parser.read(file.text)
    parser.finish()
    return parser.to_result()


def main():
    args = parse_args()
    try:
        lint_targets = decomplint_parse_args(args)
    except RecCmpProjectException as e:
        logger.error("%s", e.args[0])
        return 1

    # Dedupe paths before opening
    all_paths = set(
        (path, target.encoding) for target in lint_targets for path in target.paths
    )

    all_files = {}
    all_alerts = []
    for path, encoding in all_paths:
        try:
            file = TextFile.from_file(path, encoding=encoding)
            all_files[(path, encoding)] = parse_file(file)

        except FileNotFoundError:
            all_alerts.append(
                ParserAlert(code=AlertCode.FILE_NOT_FOUND, path=path, line_number=-1)
            )

        except UnicodeDecodeError:
            # Encoding is here as the "line" of the alert just so it's displayed to the user.
            all_alerts.append(
                ParserAlert(
                    code=AlertCode.UNICODE_DECODE_ERROR,
                    path=path,
                    line_number=-1,
                    line=encoding,
                )
            )

    # Collect parser errors and linter errors for single files:
    for (path, _), result in all_files.items():
        all_alerts.extend(result.alerts)
        all_alerts.extend(check_byname_allowed(result))
        all_alerts.extend(check_function_order(result))

    # Lint each grouping of files from each linter target.
    for target in lint_targets:
        parsed_files = [
            all_files[(path, target.encoding)]
            for path in target.paths
            if (path, target.encoding) in all_files
        ]

        scoped_alerts = lint_file_collections(parsed_files, module=target.module)
        all_alerts.extend(scoped_alerts)

    error_count = 0
    warning_count = 0

    # Group alerts by path
    total_alerts: dict[PurePath, list[ParserAlert]] = {}

    for alert in all_alerts:
        # Filter out errors from other modules
        if args.target is None or args.target == alert.target or alert.target is None:
            total_alerts.setdefault(alert.path, []).append(alert)

    # Paths were accumulated using a set(), so we have to sort again.
    sorted_paths = sorted(total_alerts.keys(), key=lambda p: str(p).lower())
    for error_path in sorted_paths:
        alerts = total_alerts[error_path]

        if alerts:
            error_count += sum(1 for alert in alerts if alert.is_error())
            warning_count += sum(1 for alert in alerts if alert.is_warning())

            sorted_alerts = sorted(alerts, key=lambda a: a.line_number)
            display_errors(sorted_alerts, error_path)
            print()

    print(colorama.Style.RESET_ALL, end="")

    would_fail = error_count > 0 or (warning_count > 0 and args.warnfail)
    if would_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
