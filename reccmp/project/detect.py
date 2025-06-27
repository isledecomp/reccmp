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
    ProjectFileTarget,
    UserFile,
    UserFileTarget,
)

from .common import RECCMP_USER_CONFIG, RECCMP_BUILD_CONFIG, RECCMP_PROJECT_CONFIG
from .error import (
    RecCmpProjectException,
    RecCmpProjectNotFoundException,
    InvalidRecCmpProjectException,
    InvalidRecCmpArgumentException,
    UnknownRecCmpTargetException,
)
from .util import get_path_sha256


logger = logging.getLogger(__file__)


def verify_target_names(
    project_targets: dict[str, ProjectFileTarget],
    user_targets: dict[str, UserFileTarget],
    build_targets: dict[str, BuildFileTarget],
):
    """Warn if the user or build files have different targets than the canonical list in the project file."""
    project_keys = set(project_targets.keys())
    user_keys = set(user_targets.keys())
    build_keys = set(build_targets.keys())
    if project_keys - user_keys:
        logger.warning("User config %s is missing target ids", RECCMP_USER_CONFIG)
    if user_keys - project_keys:
        logger.warning(
            "User config %s contains too many target ids", RECCMP_USER_CONFIG
        )
    if project_keys - build_keys:
        logger.warning("Build config %s is missing target ids", RECCMP_BUILD_CONFIG)
    if build_keys - project_keys:
        logger.warning(
            "Build config %s contains too many target ids", RECCMP_BUILD_CONFIG
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
class RecCmpTarget:
    """Partial information for a target (binary file) in the decomp project
    This contains only the static information (same for all users).
    Saved to project.yml. (See ProjectFileTarget)"""

    # Unique ID for grouping the metadata.
    # If none is given we will use the base filename minus the file extension.
    target_id: str | None

    # Base filename (not a path) of the binary for this target.
    # "reccmp-project detect" uses this to search for the original and recompiled binaries
    # when creating the user.yml file.
    filename: str

    # Relative (to project root) directory of source code files for this target.
    source_root: Path

    # Ghidra-specific options for this target.
    ghidra_config: GhidraConfig


@dataclass
class RecCmpBuiltTarget(RecCmpTarget):
    """Full information for a target. Used to load component files for reccmp analysis."""

    original_path: Path
    recompiled_path: Path
    recompiled_pdb: Path


class RecCmpProject:
    def __init__(
        self,
        project_config_path: Path,
    ):
        self.project_config_path = project_config_path
        self.targets: dict[str, RecCmpTarget] = {}

    @classmethod
    def from_directory(cls, directory: Path) -> "RecCmpProject | None":
        project_directory: Path | None
        build_directory = find_filename_recursively(
            directory=directory, filename=RECCMP_BUILD_CONFIG
        )
        if build_directory:
            build_config = build_directory / RECCMP_BUILD_CONFIG
            logger.debug("Using build config: %s", build_config)
            build_data = BuildFile.from_file(build_config)

            # The project directory can be relative to the build config
            project_directory = build_config.parent.joinpath(build_data.project)
        else:
            project_directory = find_filename_recursively(
                directory=directory, filename=RECCMP_PROJECT_CONFIG
            )
            if not project_directory:
                return None
        project_config_path = project_directory / RECCMP_PROJECT_CONFIG

        project = cls(
            project_config_path=project_config_path,
        )
        logger.debug("Using project config: %s", project_config_path)
        project_data = ProjectFile.from_file(project_config_path)

        for target_id, project_target_data in project_data.targets.items():
            source_root = project_directory / project_target_data.source_root
            filename = project_target_data.filename

            ghidra = GhidraConfig(
                ignore_types=project_target_data.ghidra.ignore_types,
                ignore_functions=project_target_data.ghidra.ignore_functions,
            )

            project.targets[target_id] = RecCmpTarget(
                target_id=target_id,
                filename=filename,
                source_root=source_root,
                ghidra_config=ghidra,
            )
        return project


class RecCmpBuiltProject:
    """Combines information from the project, user, and build yml files."""

    def __init__(
        self,
        project_config_path: Path,
        user_config: Path,
        build_config: Path,
    ):
        self.project_config_path = project_config_path
        self.user_config = user_config
        self.build_config = build_config
        self.targets: dict[str, RecCmpBuiltTarget] = {}

    @classmethod
    def from_directory(cls, directory: Path) -> "RecCmpBuiltProject":
        # Searching for build.yml
        build_directory = find_filename_recursively(
            directory=directory, filename=RECCMP_BUILD_CONFIG
        )
        if not build_directory:
            raise RecCmpProjectNotFoundException(
                f"Cannot find {RECCMP_BUILD_CONFIG} under {build_directory}"
            )
        build_config = build_directory / RECCMP_BUILD_CONFIG
        logger.debug("Using build config: %s", build_config)

        # Parse build.yml
        build_data = BuildFile.from_file(build_config)

        # Searching for project.yml
        # note that Path.joinpath() will ignore the first path if the second path is absolute
        project_directory = build_directory.joinpath(build_data.project)
        project_config_path = project_directory / RECCMP_PROJECT_CONFIG
        if not project_config_path.is_file():
            raise InvalidRecCmpProjectException(
                f"{build_config}: .project is invalid ({project_config_path} does not exist)"
            )
        logger.debug("Using project config: %s", project_config_path)

        # Parse project.yml
        project_data = ProjectFile.from_file(project_config_path)

        # Searching for user.yml
        user_config = project_directory / RECCMP_USER_CONFIG
        if not user_config.is_file():
            raise InvalidRecCmpProjectException(
                f"Missing {RECCMP_USER_CONFIG}. First run 'reccmp-project detect'."
            )
        logger.debug("Using user config: %s", user_config)

        # Parse user.yml
        user_data = UserFile.from_file(user_config)

        verify_target_names(
            project_targets=project_data.targets,
            user_targets=user_data.targets,
            build_targets=build_data.targets,
        )

        project = cls(
            project_config_path=project_config_path,
            user_config=user_config,
            build_config=build_config,
        )

        # For each target in the project file, combine information from user and build files.
        for target_id, project_target_data in project_data.targets.items():
            user_target_data = user_data.targets.get(target_id, None)
            build_target_data = build_data.targets.get(target_id, None)

            # Skip this target if the build or user files do not have it.
            if not user_target_data:
                logger.warning(
                    "%s: targets.%s is missing. Target will not be available.",
                    user_config,
                    target_id,
                )
                continue

            if not build_target_data:
                logger.warning(
                    "%s: targets.%s is missing. Target will not be available.",
                    build_config,
                    target_id,
                )
                continue

            source_root = project_directory / project_target_data.source_root
            filename = project_target_data.filename
            original_path = user_target_data.path

            recompiled_path = build_directory.joinpath(build_target_data.path)
            recompiled_pdb = build_directory.joinpath(build_target_data.pdb)

            ghidra = GhidraConfig(
                ignore_types=project_target_data.ghidra.ignore_types,
                ignore_functions=project_target_data.ghidra.ignore_functions,
            )

            project.targets[target_id] = RecCmpBuiltTarget(
                target_id=target_id,
                filename=filename,
                original_path=original_path,
                recompiled_path=recompiled_path,
                recompiled_pdb=recompiled_pdb,
                source_root=source_root,
                ghidra_config=ghidra,
            )
        return project


class RecCmpPathsAction(argparse.Action):
    def __call__(
        self, parser, namespace, values: Sequence[str] | None, option_string=None
    ):
        assert isinstance(values, Sequence)
        target_id, source_root = values
        target = RecCmpTarget(
            target_id=target_id,
            filename="???",
            source_root=Path(source_root),
            ghidra_config=GhidraConfig(),
        )
        setattr(namespace, self.dest, target)


class RecCmpBuiltPathsAction(argparse.Action):
    def __call__(
        self, parser, namespace, values: Sequence[str] | None, option_string=None
    ):
        assert isinstance(values, Sequence)
        original, recompiled, pdb, source_root = list(Path(o) for o in values)
        target = RecCmpBuiltTarget(
            target_id=None,
            filename=original.name,
            original_path=original,
            recompiled_path=recompiled,
            recompiled_pdb=pdb,
            source_root=source_root,
            ghidra_config=GhidraConfig(),
        )
        setattr(namespace, self.dest, target)


def argparse_add_project_target_args(parser: argparse.ArgumentParser):
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target", metavar="<target-id>", help="ID of the target"
    )
    target_group.add_argument(
        "--module-and-path",
        metavar=("<module-id>", "<source-root>"),
        nargs=2,
        action=RecCmpPathsAction,
        dest="target",
        help="The original binary, the recompiled binary, the PDB of the recompiled binary, and the source root",
    )
    parser.add_argument(
        "--path",
        dest="path_target",
        type=Path,
        metavar="<source-root>",
        default=Path.cwd(),
        help="The source root",
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
        if args.target not in project.targets:
            raise InvalidRecCmpArgumentException(
                f"Invalid --target: must be one of {','.join(project.targets)}"
            )
        target = project.targets[args.target]
    else:
        target = args.path_target

    if not target.source_root.is_dir():
        raise RecCmpProjectNotFoundException(
            f"Source directory {target.source_root} does not exist"
        )
    return target


def argparse_add_built_project_target_args(parser: argparse.ArgumentParser):
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
        action=RecCmpBuiltPathsAction,
        dest="paths_target",
        help="The original binary, the recompiled binary, the PDB of the recompiled binary, and the source root",
    )


def argparse_parse_built_project_target(
    args: argparse.Namespace,
) -> RecCmpBuiltTarget:
    if args.target:
        project = RecCmpBuiltProject.from_directory(Path.cwd())
        if not project:
            raise RecCmpProjectNotFoundException(
                f"Cannot find a reccmp project (missing {RECCMP_PROJECT_CONFIG}/{RECCMP_BUILD_CONFIG})"
            )
        if args.target not in project.targets:
            raise UnknownRecCmpTargetException(
                f"Invalid --target: must be one of {','.join(project.targets)}"
            )
        target = project.targets[args.target]
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
            missing = filename
            for search_path_folder in search_path:
                p = search_path_folder / filename
                pdb = p.with_suffix(".pdb")
                if p.is_file():
                    if pdb.is_file():
                        build_data.targets.setdefault(
                            target_id, BuildFileTarget(path=p, pdb=pdb)
                        )
                        logger.info("Found %s -> %s", target_id, p)
                        logger.info("Found %s -> %s", target_id, pdb)
                        break
                    else:
                        missing = pdb.name
            else:
                logger.warning("Could not find %s", missing)
        logger.info("Updating %s", build_config_path)
        build_data.write_file(build_config_path)
