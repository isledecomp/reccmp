#!/usr/bin/env python
import argparse
import logging
import enum
from pathlib import Path

import reccmp
from reccmp.project.error import RecCmpProjectException
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging
from reccmp.project.create import create_project
from reccmp.project.detect import (
    RecCmpProject,
    detect_project,
    DetectWhat,
)


logger = logging.getLogger(__name__)


class ProjectSubcommand(enum.Enum):
    CREATE = enum.auto()
    DETECT = enum.auto()


def main():
    parser = argparse.ArgumentParser(
        description="Project management", allow_abbrev=False
    )
    parser.set_defaults(subcommand=None)
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    parser.add_argument(
        "-C",
        type=Path,
        dest="cwd",
        metavar="<path>",
        default=Path.cwd(),
        help="Run as if %(prog)s was started in %(metavar)s",
    )
    subparsers = parser.add_subparsers(required=True)

    create_parser = subparsers.add_parser("create")
    create_parser.set_defaults(subcommand=ProjectSubcommand.CREATE)
    create_parser.add_argument(
        "--originals",
        type=Path,
        nargs="+",
        metavar="ORIGINAL",
        dest="create_originals",
        required=True,
        help="Path(s) of original executable(s)",
    )
    create_parser.add_argument(
        "--path",
        metavar="<project-directory>",
        dest="create_directory",
        type=Path,
        default=Path.cwd(),
        help="Location where to create reccmp project",
    )
    create_parser.add_argument(
        "--cmake-project",
        action="store_true",
        dest="create_cmake",
        help="Create minimal CMake project",
    )
    create_parser.add_argument(
        "--scm",
        action="store_true",
        dest="create_scm",
        help="Update SCM ignore files (.gitignore)",
    )

    detect_parser = subparsers.add_parser("detect")
    detect_parser.set_defaults(subcommand=ProjectSubcommand.DETECT)
    detect_parser.add_argument(
        "--search-path",
        nargs="+",
        dest="detect_search_path",
        type=Path,
        metavar="<path>",
        default=[Path.cwd()],
        help="Directory in which to look for original binaries",
    )
    detect_parser.add_argument(
        "--what",
        choices=(DetectWhat.ORIGINAL, DetectWhat.RECOMPILED),
        type=DetectWhat,
        default=DetectWhat.ORIGINAL,
        dest="detect_what",
        help="Detect original or recompiled binaries (default is original)",
    )

    argparse_add_logging_args(parser=parser)

    args = parser.parse_args()

    argparse_parse_logging(args=args)

    if args.subcommand == ProjectSubcommand.CREATE:
        try:
            # pylint: disable=unused-argument
            project: RecCmpProject | None = create_project(
                project_directory=args.create_directory,
                original_paths=args.create_originals,
                scm=args.create_scm,
                cmake=args.create_cmake,
            )
            return 0
        except RecCmpProjectException as e:
            logger.error("Project creation failed: %s", e.args[0])

    elif args.subcommand == ProjectSubcommand.DETECT:
        project = RecCmpProject.from_directory(Path.cwd())
        if project is None:
            parser.error(
                f"Cannot find reccmp project. Run '{parser.prog} create' first."
            )
        try:
            detect_project(
                project_directory=project.project_config_path.parent,
                search_path=args.detect_search_path,
                detect_what=args.detect_what,
                build_directory=Path.cwd(),
            )
            return 0
        except RecCmpProjectException as e:
            logger.error("Project detection failed: %s", e.args[0])

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
