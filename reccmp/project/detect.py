import argparse
import enum
import logging
from pathlib import Path
import typing

import ruamel.yaml

from .config import BuildFile, BuildFileTarget, GhidraConfig, ProjectFile, ProjectFileTarget, RecCmpBuiltTarget, RecCmpTarget, UserFile, UserFileTarget

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


def find_filename_recursively(directory: Path, filename: str) -> typing.Optional[Path]:
    """
    Find filename in working directory, or parent directories.
    """
    if (directory / filename).exists():
        return directory
    for parent in directory.parents:
        if (parent / filename).exists():
            return parent
    return None


class RecCmpProject:
    def __init__(
        self,
        project_config_path: Path,
    ):
        self.project_config_path = project_config_path
        self.targets: dict[str, RecCmpTarget] = {}

    @classmethod
    def from_directory(cls, directory: Path) -> typing.Optional["RecCmpProject"]:
        build_directory = find_filename_recursively(
            directory=directory, filename=RECCMP_BUILD_CONFIG
        )
        yaml_loader = ruamel.yaml.YAML()
        if build_directory:
            build_config = build_directory / RECCMP_BUILD_CONFIG
            logger.debug("Using build config: %s", build_config)
            with build_config.open() as buildfile:
                build_data = BuildFile.model_validate(yaml_loader.load(buildfile))

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
        with project_config_path.open() as projectfile:
            project_data = ProjectFile.model_validate(yaml_loader.load(projectfile))

        for target_id, project_target_data in project_data.targets.items():
            source_root = project_directory / project_target_data.source_root
            filename = project_target_data.filename

            project.targets[target_id] = RecCmpTarget(
                target_id=target_id,
                filename=filename,
                source_root=source_root,
                ghidra_config=project_target_data.ghidra,
            )
        return project


class RecCmpBuiltProject:
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
        build_directory = find_filename_recursively(
            directory=directory, filename=RECCMP_BUILD_CONFIG
        )
        if not build_directory:
            raise RecCmpProjectNotFoundException(f"Cannot find {RECCMP_BUILD_CONFIG}")
        build_config = build_directory / RECCMP_BUILD_CONFIG
        logger.debug("Using build config: %s", build_config)
        yaml_loader = ruamel.yaml.YAML()
        with build_config.open() as buildfile:
            build_data = BuildFile.model_validate(yaml_loader.load(buildfile))

        # note that Path.joinpath() will ignore the first path if the second path is absolute
        project_directory = build_directory.joinpath(build_data.project)
        project_config_path = project_directory / RECCMP_PROJECT_CONFIG
        if not project_config_path.is_file():
            raise InvalidRecCmpProjectException(
                f"{build_config}: .project is invalid ({project_config_path} does not exist)"
            )
        logger.debug("Using project config: %s", project_config_path)
        with project_config_path.open() as projectfile:
            project_data = ProjectFile.model_validate(yaml_loader.load(projectfile))

        user_config = project_directory / RECCMP_USER_CONFIG
        if not user_config.is_file():
            raise InvalidRecCmpProjectException(
                f"Missing {RECCMP_USER_CONFIG}. First run 'reccmp-project detect'."
            )
        logger.debug("Using user config: %s", user_config)
        with user_config.open() as userfile:
            user_data = UserFile.model_validate(yaml_loader.load(userfile))

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
        for target_id, project_target_data in project_data.targets.items():
            user_target_data = user_data.targets.get(target_id, None)
            build_target_data = build_data.targets.get(target_id, None)

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
            if not filename:
                raise InvalidRecCmpProjectException(
                    f"{project_config_path}: targets.{target_id}.filename is missing"
                )

            original_path = user_target_data.path

            recompiled_path = build_directory.joinpath(build_target_data.path)
            recompiled_pdb = build_directory.joinpath(build_target_data.pdb)

            project.targets[target_id] = RecCmpBuiltTarget(
                target_id=target_id,
                filename=filename,
                original_path=original_path,
                recompiled_path=recompiled_path,
                recompiled_pdb=recompiled_pdb,
                source_root=source_root,
                ghidra_config=project_target_data.ghidra,
            )
        return project


class RecCmpPathsAction(argparse.Action):
    def __call__(self, parser, namespace, values: tuple[str, str], option_string=None):
        target_id, source_root = values
        source_root = Path(source_root)
        target = RecCmpTarget(
            target_id=target_id,
            filename="???",
            source_root=source_root,
            ghidra_config=GhidraConfig.default(),
        )
        setattr(namespace, self.dest, target)


class RecCmpBuiltPathsAction(argparse.Action):
    def __call__(
        self, parser, namespace, values: tuple[str, str, str, str], option_string=None
    ):
        original, recompiled, pdb, source_root = list(Path(o) for o in values)
        target = RecCmpBuiltTarget(
            target_id="???",
            filename=original.name,
            original_path=original,
            recompiled_path=recompiled,
            recompiled_pdb=pdb,
            source_root=source_root,
            ghidra_config=GhidraConfig.default(),
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
    build_directory: typing.Optional[Path] = None,
) -> None:
    yaml = ruamel.yaml.YAML()

    project_config_path = project_directory / RECCMP_PROJECT_CONFIG
    with project_config_path.open() as f:
        project_data = ProjectFile.model_validate(yaml.load(stream=f))

    if detect_what == DetectWhat.ORIGINAL:
        user_config_path = project_directory / RECCMP_USER_CONFIG
        if user_config_path.is_file():
            with user_config_path.open() as f:
                user_data = UserFile.model_validate(yaml.load(stream=f))
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
                logger.warning("Could not find %s under %s", filename, search_path_folder)

        logger.info("Updating %s", user_config_path)
        with user_config_path.open("w") as f:
            yaml.dump(data=user_data.model_dump(mode="json"), stream=f)

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

        with build_config_path.open("w") as f:
            yaml.dump(data=build_data.model_dump(mode="json"), stream=f)
