#!/usr/bin/env python3

import argparse
import logging
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Iterable
import colorama
import reccmp
import reccmp.color
from reccmp.dir import source_code_search
from reccmp.parser import DecompParser, ReccmpParserResult
from reccmp.parser.marker import MarkerType, ProjectAliases, normalize_project_aliases
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
from reccmp.project.logging import (
    argparse_add_logging_args,
    argparse_parse_logging,
)
from reccmp.project.detect import RecCmpProject
from reccmp.formats import TextFile

logger = logging.getLogger(__name__)

colorama.just_fix_windows_console()


def display_errors(alerts: Iterable[ParserAlert], filename: Path | PurePath):
    sorted_alerts = sorted(alerts, key=lambda a: a.line_number)

    print(reccmp.color.Fore.LIGHTWHITE_EX, end="")
    print(filename)

    for alert in sorted_alerts:
        line_number = alert.line_number if alert.line_number > 0 else ""
        error_type = (
            f"{reccmp.color.Fore.RED}error: "
            if alert.is_error()
            else f"{reccmp.color.Fore.YELLOW}warning: "
        )
        components = [
            "  ",
            reccmp.color.Fore.LIGHTWHITE_EX,
            f"{line_number:4}",
            " : ",
            " ",
            error_type,
            reccmp.color.Fore.LIGHTWHITE_EX,
            f"[{alert.target}] " if alert.target else "",
            alert.code.name.lower(),
        ]
        print("".join(components), end="")

        if alert.detail is not None:
            print(f"{reccmp.color.Fore.WHITE}  {alert.detail}", end="")

        print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Syntax checking and linting for decomp annotation markers."
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    # Syntax errors are always displayed in any file we parse.
    # The --target option shows linter errors for that target only.
    # If <paths> are not provided, use the code directories for that
    # target in the project file. --module is a legacy option kept
    # for compatibility. New CI scripts should use --target.
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
        default="utf-8",
        type=str,
        help="The encoding of the checked files.",
    )
    argparse_add_logging_args(parser)

    args = parser.parse_args()

    argparse_parse_logging(args)

    return args


@dataclass
class DecomplintTarget:
    paths: tuple[Path, ...]
    module: str | None
    encoding: str
    # Project-file only:
    project_file_path: Path | None = None
    aliases: dict[str, str] | None = None


def decomplint_parse_args(
    args: argparse.Namespace,
) -> tuple[DecomplintTarget, ...]:
    """Produce a list of scopes and files to check from the command-line args:
    1. No arguments: Lint each target separately
    2. Target: Lint its files only
    3. List of paths: Lint these files (with optional target scope)
    """
    if args.paths:
        paths = tuple(source_code_search(args.paths))
        module = args.target
        encoding = args.encoding

        return (DecomplintTarget(paths, module, encoding),)

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
        encoding = target.encoding or "utf-8"

        options.append(
            DecomplintTarget(
                paths,
                module,
                encoding,
                project_file_path=project.project_config_path,
                aliases=target.marker_aliases,
            )
        )

    return tuple(options)


def parse_file(file: TextFile, aliases: ProjectAliases | None) -> ReccmpParserResult:
    parser = DecompParser(aliases)
    parser.reset_and_set_filename(file.path)
    parser.read(file.text)
    parser.finish()
    return parser.to_result()


def check_aliases(lint_targets: tuple[DecomplintTarget, ...]) -> list[ParserAlert]:
    """Verify the marker aliases applied to each target."""
    builtin_types = {t.name for t in MarkerType}
    alerts = []

    for target in lint_targets:
        if target.aliases is None:
            continue

        # mypy
        project_file_path = target.project_file_path or PurePath("")

        assert isinstance(target.aliases, dict)

        seen_keys = set()
        for key, value in target.aliases.items():
            if key.upper() in builtin_types:
                alerts.append(
                    ParserAlert(
                        code=AlertCode.ALIAS_REDEFINES_BUILTIN,
                        path=project_file_path,
                        detail=f"{key} : {value}",
                        target=target.module,
                    )
                )

            if value.upper() not in builtin_types:
                alerts.append(
                    ParserAlert(
                        code=AlertCode.ALIAS_GOES_NOWHERE,
                        path=project_file_path,
                        detail=f"{key} : {value}",
                        target=target.module,
                    )
                )

            if key.upper() in seen_keys:
                alerts.append(
                    ParserAlert(
                        code=AlertCode.ALIAS_DUPLICATE_KEY,
                        path=project_file_path,
                        detail=f"{key} : {value}",
                        target=target.module,
                    )
                )

            seen_keys.add(key.upper())

    return alerts


def lint_all_targets(lint_targets: tuple[DecomplintTarget, ...]) -> list[ParserAlert]:
    """Lint each collection of files and optional target scope.
    Returns unsorted list of parser/linter alerts."""

    # Collect all path and encoding combinations before starting.
    # Targets may share common directories, so deduplicate the paths.
    # In the unlikely event that the same path appears with different encodings,
    # try to open using each encoding and report an error if (when) this fails.
    all_paths = set(
        (path, target.encoding) for target in lint_targets for path in target.paths
    )

    # Collect all parser/linter alerts here and worry about sorting/collating later.
    all_alerts = []

    # Combine aliases for each target by their target name.
    # We need them all together because we read all markers from all files once.
    # (It's not currently possible to provide aliases at the command line.)
    project_aliases = {
        target.module: target.aliases
        for target in lint_targets
        if target.module is not None and target.aliases is not None
    }
    project_aliases = normalize_project_aliases(project_aliases)

    # Open each (path, encoding) combination once, then collect code annotations.
    parser_results = {}
    for path, encoding in all_paths:
        try:
            file = TextFile.from_file(path, encoding=encoding)
            parser_results[(path, encoding)] = parse_file(file, project_aliases)

        except FileNotFoundError:
            all_alerts.append(ParserAlert(code=AlertCode.FILE_NOT_FOUND, path=path))

        except UnicodeDecodeError:
            all_alerts.append(
                ParserAlert(
                    code=AlertCode.UNICODE_DECODE_ERROR,
                    path=path,
                    detail=encoding,
                )
            )

    # For each parsed file: add alerts that should appear only once
    for (path, _), result in parser_results.items():
        # Add parser syntax errors.
        all_alerts.extend(result.alerts)
        # Add any errors from these linter checks.
        all_alerts.extend(check_byname_allowed(result))
        all_alerts.extend(check_function_order(result))

    # Lint each collection of files from each linter target.
    for target in lint_targets:
        parsed_files = [
            parser_results[(path, target.encoding)]
            for path in target.paths
            if (path, target.encoding) in parser_results
        ]

        scoped_alerts = lint_file_collections(parsed_files, module=target.module)
        all_alerts.extend(scoped_alerts)

    return all_alerts


def main() -> int:
    args = parse_args()
    try:
        lint_targets = decomplint_parse_args(args)
    except RecCmpProjectException as e:
        logger.error("%s", e.args[0])
        return 1

    all_alerts = lint_all_targets(lint_targets)
    all_alerts.extend(check_aliases(lint_targets))

    # Finished linting: report errors.
    error_count = 0
    warning_count = 0

    # Alerts are unsorted. Prepare to group by path.
    filtered_alerts_by_path: dict[PurePath, list[ParserAlert]] = {}

    for alert in all_alerts:
        # If we ran with --target, filter out errors from other targets.
        if args.target is None or args.target == alert.target or alert.target is None:
            filtered_alerts_by_path.setdefault(alert.path, []).append(alert)

    # Sort paths so alerts are displayed in a consistent order.
    sorted_paths = sorted(filtered_alerts_by_path.keys(), key=lambda p: str(p).lower())
    for error_path in sorted_paths:
        alerts = filtered_alerts_by_path[error_path]

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
