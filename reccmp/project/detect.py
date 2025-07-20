import argparse
import enum
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from .config import (
    BuildFile,
    BuildFileTarget,
    ProjectFile,
    UserFile,
    UserFileTarget,
)

from .common import RECCMP_USER_CONFIG, RECCMP_BUILD_CONFIG, RECCMP_PROJECT_CONFIG
from .error import (
    RecCmpProjectException,
    RecCmpProjectNotFoundException,
    InvalidRecCmpProjectException,
    UnknownRecCmpTargetException,
    IncompleteReccmpTargetError,
)
from .util import get_path_sha256


logger = logging.getLogger(__file__)


def verify_target_names(
    project_keys: set[str], user_keys: set[str], build_keys: set[str]
):
    """Warn if the user or build files have different targets than the canonical list in the project file."""
    user_missing_keys = project_keys - user_keys
    user_extra_keys = user_keys - project_keys

    if user_missing_keys:
        logger.warning(
            "User config %s is missing target ids: %s",
            RECCMP_USER_CONFIG,
            ",".join(user_missing_keys),
        )

    if user_extra_keys:
        logger.warning(
            "User config %s contains extra target ids: %s",
            RECCMP_USER_CONFIG,
            ",".join(user_extra_keys),
        )

    build_missing_keys = project_keys - build_keys
    build_extra_keys = build_keys - project_keys

    if build_missing_keys:
        logger.warning(
            "Build config %s is missing target ids: %s",
            RECCMP_BUILD_CONFIG,
            ",".join(build_missing_keys),
        )

    if build_extra_keys:
        logger.warning(
            "Build config %s contains extra target ids: %s",
            RECCMP_BUILD_CONFIG,
            ",".join(build_extra_keys),
        )


def find_filename_recursively(directory: Path, filename: str) -> Path | None:
    """
    Find filename in working directory, or parent directories.
    """
    if (directory / filename).exists():
        return directory
    for parent in directory.parents:
        if (parent / filename).exists():
            return parent
    return None


@dataclass
class GhidraConfig:
    ignore_types: list[str] = field(default_factory=list)
    ignore_functions: list[int] = field(default_factory=list)


@dataclass
class ReportConfig:
    ignore_functions: list[str] = field(default_factory=list)


@dataclass
class RecCmpPartialTarget:
    # pylint: disable=too-many-instance-attributes
    """Partial information for a target, which includes:
    - Path to the binary file being decompiled/analyzed.
    - Metadata to help locate that binary file on each user's system.
    - Path the recompiled binary for comparison.
    - Paths to the source code, pdb, and other data sources.
    - Analysis and data export options.
    The target is created by combining information from the three config files:
    reccmp-project.yml, reccmp-user.yml, and reccmp-build.yml."""

    # Unique ID for grouping the metadata.
    # If none is given we will use the base filename minus the file extension.
    target_id: str

    # Base filename (not a path) of the binary for this target.
    # "reccmp-project detect" uses this to search for the original and recompiled binaries
    # when creating the reccmp-user.yml file.
    filename: str

    # SHA-256 checksum of the original binary.
    sha256: str

    # Ghidra-specific options for this target.
    ghidra_config: GhidraConfig | None = None

    # Report options for this target
    report_config: ReportConfig | None = None

    # Relative (to project root) directory of source code files for this target.
    source_root: Path | None = None
    original_path: Path | None = None
    recompiled_path: Path | None = None
    recompiled_pdb: Path | None = None


@dataclass
class RecCmpTarget:
    # pylint: disable=too-many-instance-attributes
    """Full information for a target. This has the same attributes as RecCmpPartialTarget
    but with more strict datatypes. A project will only create this record if we can
    guarantee that the target has the minimum viable set of attributes."""

    # Unique ID for grouping the metadata.
    # If none is given we will use the base filename minus the file extension.
    target_id: str

    # Base filename (not a path) of the binary for this target.
    # "reccmp-project detect" uses this to search for the original and recompiled binaries
    # when creating the reccmp-user.yml file.
    filename: str

    # SHA-256 checksum of the original binary.
    sha256: str

    # Relative (to project root) directory of source code files for this target.
    source_root: Path

    # Ghidra-specific options for this target.
    ghidra_config: GhidraConfig

    # Report options for this target
    report_config: ReportConfig

    original_path: Path
    recompiled_path: Path
    recompiled_pdb: Path


class RecCmpProject:
    """Combines information from the project, user, and build yml files."""

    project_config_path: Path | None
    build_config_path: Path | None
    user_config_path: Path | None
    targets: dict[str, RecCmpPartialTarget]

    def __init__(
        self,
        project_config_path: Path | None = None,
        user_config_path: Path | None = None,
        build_config_path: Path | None = None,
    ):
        self.project_config_path = project_config_path
        self.user_config_path = user_config_path
        self.build_config_path = build_config_path
        self.targets = {}

    def get(self, target_id: str) -> RecCmpTarget:
        try:
            target = self.targets[target_id]
        except KeyError as ex:
            raise UnknownRecCmpTargetException(
                f"Invalid target: must be one of {','.join(self.targets.keys())}"
            ) from ex

        # Make sure we have the minimum set of attributes.
        # The error message should display the full list of missing attributes
        # so we check it here instead of waiting for a single assert to fail.
        required_attrs = (
            "source_root",
            "original_path",
            "recompiled_path",
            "recompiled_pdb",
        )

        missing_attrs = [
            attr for attr in required_attrs if getattr(target, attr) is None
        ]
        if missing_attrs:
            raise IncompleteReccmpTargetError(
                f"Target {target_id} is missing data: {','.join(missing_attrs)}"
            )

        # This list should match the one above. These asserts are for mypy.
        assert target.source_root is not None
        assert target.original_path is not None
        assert target.recompiled_path is not None
        assert target.recompiled_pdb is not None

        if target.ghidra_config is not None:
            ghidra = target.ghidra_config
        else:
            ghidra = GhidraConfig()

        if target.report_config is not None:
            report = target.report_config
        else:
            report = ReportConfig()

        return RecCmpTarget(
            target_id=target.target_id,
            filename=target.filename,
            sha256=target.sha256,
            original_path=target.original_path,
            recompiled_path=target.recompiled_path,
            recompiled_pdb=target.recompiled_pdb,
            source_root=target.source_root,
            ghidra_config=ghidra,
            report_config=report,
        )

    def find_build_config(self, search_path: Path) -> BuildFile | None:
        build_directory = find_filename_recursively(
            directory=search_path, filename=RECCMP_BUILD_CONFIG
        )

        if not build_directory:
            return None

        self.build_config_path = build_directory / RECCMP_BUILD_CONFIG
        logger.debug("Using build config: %s", self.build_config_path)
        return BuildFile.from_file(self.build_config_path)

    def find_project_config(self, search_path: Path) -> ProjectFile | None:
        project_directory = find_filename_recursively(
            directory=search_path, filename=RECCMP_PROJECT_CONFIG
        )

        if not project_directory:
            return None

        self.project_config_path = project_directory / RECCMP_PROJECT_CONFIG
        logger.debug("Using project config: %s", self.project_config_path)
        return ProjectFile.from_file(self.project_config_path)

    def find_user_config(self, search_path: Path) -> UserFile | None:
        user_config_path = search_path / RECCMP_USER_CONFIG
        if not user_config_path.is_file():
            return None

        self.user_config_path = user_config_path
        logger.debug("Using project config: %s", self.user_config_path)
        return UserFile.from_file(self.user_config_path)

    @classmethod
    def from_directory(cls, directory: Path) -> "RecCmpProject":
        project = cls()

        # Searching for reccmp-build.yml
        build_data = project.find_build_config(directory)

        if build_data is not None:
            assert project.build_config_path is not None
            # note that Path.joinpath() will ignore the first path if the second path is absolute
            project_search_path = project.build_config_path.joinpath(build_data.project)

            # If we found the build file, we must use its project path.
            project_data = project.find_project_config(project_search_path)
            if project_data is None:
                raise InvalidRecCmpProjectException(
                    f"{project.build_config_path}: .project is invalid ({project_search_path / RECCMP_PROJECT_CONFIG} does not exist)"
                )
        else:
            # No build file. Look for the project in the directory.
            project_data = project.find_project_config(directory)

        if project_data is None:
            raise RecCmpProjectNotFoundException(
                f"No project file in path: {directory}"
            )

        # We must have found the project if we are here.
        assert project.project_config_path is not None
        project_directory = project.project_config_path.parent
        user_data = project.find_user_config(project_directory)

        verify_target_names(
            project_keys=set(project_data.targets) if project_data else set(),
            user_keys=set(user_data.targets) if user_data else set(),
            build_keys=set(build_data.targets) if build_data else set(),
        )

        # Apply reccmp-project.yml
        assert project_data is not None
        for target_id, target in project_data.targets.items():
            if target.ghidra is not None:
                ghidra = GhidraConfig(
                    ignore_types=target.ghidra.ignore_types,
                    ignore_functions=target.ghidra.ignore_functions,
                )
            else:
                ghidra = None
            if target.report is not None:
                report = ReportConfig(
                    ignore_functions=target.report.ignore_functions,
                )
            else:
                report = None

            source_root = project_directory / target.source_root

            project.targets[target_id] = RecCmpPartialTarget(
                target_id=target_id,
                filename=target.filename,
                sha256=target.hash.sha256,
                source_root=source_root,
                ghidra_config=ghidra,
                report_config=report,
            )

        # Apply reccmp-user.yml
        if user_data is not None:
            for target_id, user_target in user_data.targets.items():
                if target_id not in project.targets:
                    continue

                project.targets[target_id].original_path = user_target.path

        # Apply reccmp-build.yml
        if build_data is not None:
            assert project.build_config_path is not None
            build_directory = project.build_config_path.parent
            for target_id, build_target in build_data.targets.items():
                if target_id not in project.targets:
                    continue

                project.targets[target_id].recompiled_path = build_directory.joinpath(
                    build_target.path
                )
                project.targets[target_id].recompiled_pdb = build_directory.joinpath(
                    build_target.pdb
                )

        return project


class RecCmpPathsAction(argparse.Action):
    def __call__(
        self, parser, namespace, values: Sequence[str] | None, option_string=None
    ):
        assert isinstance(values, Sequence)
        original, recompiled, pdb, source_root = list(Path(o) for o in values)
        target = RecCmpTarget(
            target_id=original.stem.upper(),
            filename=original.name,
            sha256=get_path_sha256(original),
            original_path=original,
            recompiled_path=recompiled,
            recompiled_pdb=pdb,
            source_root=source_root,
            ghidra_config=GhidraConfig(),
            report_config=ReportConfig(),
        )
        setattr(namespace, self.dest, target)


def argparse_add_project_target_args(parser: argparse.ArgumentParser):
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target", metavar="<target-id>", help="ID of the target"
    )
    target_group.add_argument(
        "--paths",
        metavar=(
            "<original-binary>",
            "<recompiled-binary>",
            "<recompiled-pdb>",
            "<source-root>",
        ),
        nargs=4,
        action=RecCmpPathsAction,
        dest="paths_target",
        help="The original binary, the recompiled binary, the PDB of the recompiled binary, and the source root",
    )


def argparse_parse_project_target(
    args: argparse.Namespace,
) -> RecCmpTarget:
    if args.target:
        project = RecCmpProject.from_directory(Path.cwd())
        if not project:
            raise RecCmpProjectNotFoundException(
                f"Cannot find a reccmp project (missing {RECCMP_PROJECT_CONFIG}/{RECCMP_BUILD_CONFIG})"
            )

        target = project.get(args.target)
    else:
        target = args.paths_target

    if not target.original_path.is_file():
        raise RecCmpProjectException(
            f"Original binary {target.original_path} does not exist"
        )

    if not target.recompiled_path.is_file():
        raise RecCmpProjectException(
            f"Recompiled binary {target.recompiled_path} does not exist"
        )

    if not target.recompiled_pdb.is_file():
        raise RecCmpProjectException(
            f"Symbols PDB {target.recompiled_pdb} does not exist"
        )

    if not target.source_root.is_dir():
        raise RecCmpProjectException(
            f"Source directory {target.source_root} does not exist"
        )
    return target


class DetectWhat(enum.Enum):
    ORIGINAL = "original"
    RECOMPILED = "recompiled"

    def __str__(self):
        return self.value


def detect_project(
    project_directory: Path,
    search_path: list[Path],
    detect_what: DetectWhat,
    build_directory: Path | None = None,
) -> None:
    project_config_path = project_directory / RECCMP_PROJECT_CONFIG
    project_data = ProjectFile.from_file(project_config_path)

    if detect_what == DetectWhat.ORIGINAL:
        user_config_path = project_directory / RECCMP_USER_CONFIG
        if user_config_path.is_file():
            user_data = UserFile.from_file(user_config_path)
        else:
            user_data = UserFile(targets={})

        for target_id, target_data in project_data.targets.items():
            filename = target_data.filename
            for search_path_folder in search_path:
                p = search_path_folder / filename
                if not p.is_file():
                    continue

                p_sha256 = get_path_sha256(p)
                ref_sha256 = target_data.hash.sha256
                if ref_sha256.lower() != p_sha256.lower():
                    logger.info(
                        "sha256 of '%s' (%s) does NOT match expected hash (%s)",
                        p,
                        p_sha256,
                        ref_sha256,
                    )
                    continue

                user_data.targets.setdefault(target_id, UserFileTarget(path=p))
                logger.info("Found %s -> %s", target_id, p)
                break
            else:
                logger.warning(
                    "Could not find %s under %s", filename, search_path_folder
                )

        logger.info("Updating %s", user_config_path)
        user_data.write_file(user_config_path)

    elif detect_what == DetectWhat.RECOMPILED:
        if not build_directory:
            raise RecCmpProjectException(
                "Detecting recompiled binaries requires build directory"
            )
        build_config_path = build_directory / RECCMP_BUILD_CONFIG
        build_data = BuildFile(project=project_directory.resolve(), targets={})

        for target_id, target_data in project_data.targets.items():
            filename = target_data.filename
            for search_path_folder in search_path:
                p = search_path_folder / filename
                pdb = p.with_suffix(".pdb")
                if p.is_file() and pdb.is_file():
                    build_data.targets.setdefault(
                        target_id, BuildFileTarget(path=p, pdb=pdb)
                    )
                    logger.info("Found %s -> %s", target_id, p)
                    logger.info("Found %s -> %s", target_id, pdb)
                    break
            else:
                logger.warning("Could not find %s", filename)
        logger.info("Updating %s", build_config_path)
        build_data.write_file(build_config_path)
