import argparse
import dataclasses
import enum
import logging
from pathlib import Path
import typing

import ruamel.yaml

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


@dataclasses.dataclass
class RecCmpTarget:
    target_id: str
    filename: str
    source_root: Path


@dataclasses.dataclass
class RecCmpBuiltTarget(RecCmpTarget):
    original_path: Path
    recompiled_path: Path
    recompiled_pdb: Path


def verify_target_names(
    project_targets: dict[str, typing.Any],
    user_targets: dict[str, typing.Any],
    build_targets: dict[str, typing.Any],
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
        project_config_path: typing.Optional[Path],
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
            build_data = yaml_loader.load(build_config.open())

            project_directory = Path(build_data["project"])
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
        project_data = yaml_loader.load(project_config_path.open())
        for target_id, project_target_data in project_data.get("targets").items():
            source_root = project_directory / project_target_data.get("source-root", "")
            filename = project_target_data.get("filename")
            if not filename:
                raise InvalidRecCmpProjectException(
                    f"{project_config_path}: targets.{target_id}.filename is missing"
                )

            project.targets[target_id] = RecCmpTarget(
                target_id=target_id, filename=filename, source_root=source_root
            )
        return project


class RecCmpBuiltProject:
    def __init__(
        self,
        project_config_path: typing.Optional[Path],
        user_config: typing.Optional[Path],
        build_config: typing.Optional[Path],
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
        build_data = yaml_loader.load(build_config.open())

        project_directory = Path(build_data["project"])
        project_config_path = project_directory / RECCMP_PROJECT_CONFIG
        if not project_config_path.is_file():
            raise InvalidRecCmpProjectException(
                f"{build_config}: .project is invalid ({project_config_path} does not exist)"
            )
        logger.debug("Using project config: %s", project_config_path)
        project_data = yaml_loader.load(project_config_path.open())

        user_config = project_directory / RECCMP_USER_CONFIG
        if not user_config.is_file():
            raise InvalidRecCmpProjectException(
                f"Missing {RECCMP_USER_CONFIG}. First run 'reccmp-project detect'."
            )
        logger.debug("Using user config: %s", user_config)
        user_data = yaml_loader.load(user_config.open())

        verify_target_names(
            project_targets=project_data.get("targets"),
            user_targets=user_data.get("targets"),
            build_targets=build_data.get("targets"),
        )

        project = cls(
            project_config_path=project_config_path,
            user_config=user_config,
            build_config=build_config,
        )
        for target_id, project_target_data in project_data.get("targets").items():
            user_target_data = user_data.get("targets", {}).get(target_id, {})

            source_root = project_directory / project_target_data.get("source-root", "")
            filename = project_target_data.get("filename")
            if not filename:
                raise InvalidRecCmpProjectException(
                    f"{project_config_path}: targets.{target_id}.filename is missing"
                )

            original_path_str = user_target_data.get("path")
            if not original_path_str:
                logger.warning(
                    "%s: targets.%s.path is missing. Target will not be available.",
                    user_config,
                    target_id,
                )
                continue
            original_path = Path(original_path_str.strip())

            build_target_data = build_data.get("targets", {}).get(target_id, {})

            recompiled_path_str = build_target_data.get("path")
            if not recompiled_path_str:
                logger.warning(
                    "%s: targets.%s.path is missing. Target will not be available.",
                    build_config,
                    target_id,
                )
                continue
            recompiled_path = Path(recompiled_path_str)
            recompiled_pdb_str = build_target_data.get("pdb")
            if not recompiled_path_str:
                logger.warning(
                    "%s: targets.%s.pdb is missing. Target will not be available.",
                    build_config,
                    target_id,
                )
                continue
            recompiled_pdb = Path(recompiled_pdb_str)

            project.targets[target_id] = RecCmpBuiltTarget(
                target_id=target_id,
                filename=filename,
                original_path=original_path,
                recompiled_path=recompiled_path,
                recompiled_pdb=recompiled_pdb,
                source_root=source_root,
            )
        return project


class RecCmpPathsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        target_id, source_root = values
        source_root = Path(source_root)
        target = RecCmpTarget(
            target_id=target_id,
            filename="???",
            source_root=source_root,
        )
        setattr(namespace, self.dest, target)


class RecCmpBuiltPathsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        original, recompiled, pdb, source_root = list(Path(o) for o in values)
        target = RecCmpBuiltTarget(
            target_id="???",
            filename=original.name,
            original_path=original,
            recompiled_path=recompiled,
            recompiled_pdb=pdb,
            source_root=source_root,
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
        project_data = yaml.load(stream=f)

    if detect_what == DetectWhat.ORIGINAL:
        user_config_path = project_directory / RECCMP_USER_CONFIG
        if user_config_path.is_file():
            with user_config_path.open() as f:
                user_data = yaml.load(stream=f)
        else:
            user_data = {"targets": {}}
        for target_id, target_data in project_data.get("targets", {}).items():
            ref_sha256 = (
                project_data.get("targets", {})
                .get(target_id, {})
                .get("hash", {})
                .get("sha256", None)
            )
            filename = target_data["filename"]
            for search_path_folder in search_path:
                p = search_path_folder / filename
                if not p.is_file():
                    continue
                if ref_sha256:
                    p_sha256 = get_path_sha256(p)
                    if ref_sha256.lower() != p_sha256.lower():
                        logger.info(
                            "sha256 of '%s' (%s) does NOT match expected hash (%s)",
                            p,
                            p_sha256,
                            ref_sha256,
                        )
                        continue
                user_data.setdefault("targets", {}).setdefault(
                    target_id, {}
                ).setdefault("path", str(p))
                logger.info("Found %s -> %s", target_id, p)
                break
            else:
                logger.warning("Could not find %s", filename)

        logger.info("Updating %s", user_config_path)
        with user_config_path.open("w") as f:
            yaml.dump(data=user_data, stream=f)
    elif detect_what == DetectWhat.RECOMPILED:
        if not build_directory:
            raise RecCmpProjectException(
                "Detecting recompiled binaries requires build directory"
            )
        build_config_path = build_directory / RECCMP_BUILD_CONFIG
        build_data = {
            "project": str(project_directory.resolve()),
        }
        for target_id, target_data in project_data.get("targets", {}).items():
            filename = target_data["filename"]
            for search_path_folder in search_path:
                p = search_path_folder / filename
                pdb = p.with_suffix(".pdb")
                if p.is_file() and pdb.is_file():
                    build_data.setdefault("targets", {}).setdefault(
                        target_id, {}
                    ).setdefault("path", str(p))
                    logger.info("Found %s -> %s", target_id, p)
                    logger.info("Found %s -> %s", target_id, pdb)
                    build_data.setdefault("targets", {}).setdefault(
                        target_id, {}
                    ).setdefault("pdb", str(pdb))
                    break
            else:
                logger.warning("Could not find %s", filename)
        logger.info("Updating %s", build_config_path)

        with build_config_path.open("w") as f:
            yaml.dump(data=build_data, stream=f)
