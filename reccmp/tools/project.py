#!/usr/bin/env python
import argparse
import enum
import hashlib
import itertools
import logging
from pathlib import Path
import re
import shutil
import sys
import textwrap

import ruamel.yaml
import reccmp
from reccmp.assets import get_asset_file
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging
from reccmp.project.detect import (
    RECCMP_BUILD_CONFIG,
    RECCMP_PROJECT_CONFIG,
    RECCMP_USER_CONFIG,
    RecCmpProject,
)


logger = logging.getLogger(__name__)


GITIGNORE_RULES = f"""\
{RECCMP_USER_CONFIG}
{RECCMP_BUILD_CONFIG}
"""


def path_to_id(path: Path) -> str:
    return re.sub("[^0-9a-zA-Z_]", "", path.stem.upper())


def get_path_sha256(p: Path) -> dict[str, str]:
    sha256_hasher = hashlib.sha256()
    sha256_hasher.update(p.read_bytes())
    return sha256_hasher.hexdigest()


def create_project(
    project_directory: Path, original_paths: list[Path], cmake: bool
) -> int:
    if not original_paths:
        print("Need at least one original binary", file=sys.stderr)
        return 1
    id_path = {}
    project_config = {"targets": {}}
    for original_path in original_paths:
        if not original_path.is_file():
            logger.error("Original binary (%s) is not a file", original_path)
            return 1
        target_id = path_to_id(original_path)
        hash_sha256 = get_path_sha256(original_path)
        target_data = {
            "filename": original_path.name,
            "hash": {
                "sha256": hash_sha256,
            },
        }
        if target_id in project_config["targets"]:
            for suffix_nb in itertools.count(start=0, step=1):
                new_target_id = f"{target_id}_{suffix_nb}"
                if new_target_id not in project_config["targets"]:
                    target_id = new_target_id
                    break
        project_config["targets"][target_id] = target_data
        id_path[target_id] = original_path
    project_file = project_directory / RECCMP_PROJECT_CONFIG
    project_user_file = project_directory / RECCMP_USER_CONFIG

    if project_file.exists():
        print(
            "Failed to create a new reccmp project: there already exists one.",
            file=sys.stderr,
        )
        return 1

    project_name = path_to_id(original_paths[0])
    logger.debug("Creating %s...", project_config)
    with project_file.open("w") as f:
        yaml = ruamel.yaml.YAML()
        yaml.dump(data=project_config, stream=f)

    user_config = {
        "targets": {uid: str(path.resolve()) for uid, path in id_path.items()}
    }
    logger.debug("Creating %s...", user_config)
    with project_user_file.open("w") as f:
        yaml = ruamel.yaml.YAML()
        yaml.dump(data=user_config, stream=f)

    gitignore_path = project_directory / ".gitignore"
    logger.debug("Creating %s...", gitignore_path)
    with gitignore_path.open("a") as f:
        f.write(GITIGNORE_RULES)

    if cmake:
        project_cmake_dir = project_directory / "cmake"
        project_cmake_dir.mkdir(exist_ok=True)
        logger.debug("Copying %s...", "cmake/reccmp.py")
        shutil.copy(
            get_asset_file("cmake/reccmp.cmake"),
            project_directory / "cmake/reccmp.cmake",
        )

        cmakelists_txt = get_default_cmakelists_txt(
            project_name=project_name, targets=id_path
        )
        cmakelists_path = project_directory / "CMakeLists.txt"
        logger.debug("Creating %s...", cmakelists_path)
        with cmakelists_path.open("w") as f:
            f.write(cmakelists_txt)

        for target_id, original_path in id_path.items():
            main_cpp_path = project_directory / f"main_{target_id}.cpp"
            main_hpp_path = project_directory / f"main_{target_id}.hpp"
            main_cpp = get_default_main_cpp(
                target_id=target_id, original_path=original_path, hpp_path=main_hpp_path
            )
            logger.debug("Creating %s...", main_cpp_path)
            with main_cpp_path.open("w") as f:
                f.write(main_cpp)

            main_hpp = get_default_main_hpp(target_id=target_id)
            logger.debug("Creating %s...", main_hpp_path)
            with main_hpp_path.open("w") as f:
                f.write(main_hpp)
    return 0


class DetectWhat(enum.Enum):
    ORIGINAL = "original"
    RECOMPILED = "recompiled"

    def __str__(self):
        return self.value


def detect_project(
    project_directory: Path,
    search_path: list[Path],
    detect_what: DetectWhat,
    build_directory: Path,
):
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
                    ).setdefault("pdb", str(p))
                    break
            else:
                logger.warning("Could not find %s", filename)
        logger.info("Updating %s", build_config_path)

        with build_config_path.open("w") as f:
            yaml.dump(data=build_data, stream=f)
    return 0


class TargetType(enum.Enum):
    SHARED_LIBRARY = "SHARED_LIBRARY"
    EXECUTABLE = "EXECUTABLE"


def executable_or_library(path: Path) -> TargetType:
    str_path = str(path).lower()
    if str_path.endswith(".dll"):
        return TargetType.SHARED_LIBRARY
    if str_path.endswith(".exe"):
        return TargetType.EXECUTABLE
    # FIXME: detect from file contents (or arguments?)
    raise ValueError("Unknown target type")


def get_default_cmakelists_txt(project_name: str, targets: dict[str, Path]) -> str:
    result = textwrap.dedent(
        f"""\
        cmake_minimum_required(VERSION 3.20)
        project({project_name})

        include("${{CMAKE_CURRENT_SOURCE_DIR}}/cmake/reccmp.cmake")
    """
    )

    for target_name, target_path in targets.items():
        target_type = executable_or_library(target_path)
        target_prefix = ""
        target_suffix = target_path.suffix
        if target_type == TargetType.SHARED_LIBRARY and target_name.startswith("lib"):
            target_prefix = "lib"
            target_name = target_name.removeprefix("lib")

        match target_type:
            case TargetType.EXECUTABLE:
                add_executable_or_library = "add_executable"
                maybe_shared = ""
            case TargetType.SHARED_LIBRARY:
                add_executable_or_library = "add_library"
                maybe_shared = "SHARED"
        result += "\n"
        result += textwrap.dedent(
            f"""\
            {add_executable_or_library}({target_name} {maybe_shared}
                main_{target_name}.cpp
                main_{target_name}.hpp
            )
            reccmp_add_target({target_name} ID {target_name})
            set_property(TARGET {target_name} PROPERTY OUTPUT_NAME "{target_path.stem}")
            set_property(TARGET {target_name} PROPERTY PREFIX "{target_prefix}")
            set_property(TARGET {target_name} PROPERTY SUFFIX "{target_suffix}")
        """
        )

    result += "\n"
    result += textwrap.dedent(
        """\
        reccmp_configure()
    """
    )
    return result


def get_default_main_hpp(target_id: str) -> str:
    return textwrap.dedent(
        f"""\
        #ifndef {target_id.upper()}_HPP
        #define {target_id.upper()}_HPP

        // VTABLE: {target_id} 0x10001000
        // SIZE 0x8
        class SomeClass {{
            virtual ~SomeClass(); // vtable+0x00
            int m_member;
        }};

        #endif /* {target_id.upper()}_HPP */
        """
    )


def get_default_main_cpp(target_id: str, original_path: Path, hpp_path: Path) -> str:
    target_type = executable_or_library(original_path)
    match target_type:
        case TargetType.EXECUTABLE:
            entry_function = textwrap.dedent(
                """\
                #ifdef _WIN32
                #include <windows.h>

                // FUNCTION: {original_id} 0x10000020
                int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, int nCmdShow) {
                    return 0;
                }
                #else
                // FUNCTION: {original_id} 0x10000020
                int main(int argc, char *argv[]) {
                    return 0;
                }
                #endif
            """
            )
        case TargetType.SHARED_LIBRARY:
            entry_function = textwrap.dedent(
                """\
                #ifdef _WIN32
                #include <windows.h>

                // FUNCTION: {original_id} 0x10000020
                BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved ) {
                    return TRUE;
                }
                #endif
            """
            )
    return textwrap.dedent(
        f"""\
        #include "{hpp_path.name}"

        // FUNCTION: {target_id} 0x10000000
        SomeClass::~SomeClass() {{
        }}

        // GLOBAL: {target_id} 0x10102000
        // STRING: {target_id} 0x10101f00
        const char* g_globalString = "A global string";

        {entry_function}
    """
    )


def main():
    parser = argparse.ArgumentParser(
        description="Project management", allow_abbrev=False
    )
    parser.set_defaults(action=None)
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
    subparsers = parser.add_subparsers()

    create_parser = subparsers.add_parser("create")
    create_parser.set_defaults(action="CREATE")
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

    detect_parser = subparsers.add_parser("detect")
    detect_parser.set_defaults(action="DETECT")
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

    if args.action == "CREATE":  # FIXME: use enum or callback function
        return create_project(
            project_directory=args.create_directory,
            original_paths=args.create_originals,
            cmake=args.create_cmake,
        )

    if args.action == "DETECT":  # FIXME: use enum or callback function
        project = RecCmpProject.from_directory(Path.cwd())
        if not project:
            parser.error(f"Cannot find reccmp project. Run '{parser.prog} create' first.")
        return detect_project(
            project_directory=project.project_config.parent,
            search_path=args.detect_search_path,
            detect_what=args.detect_what,
            build_directory=Path.cwd(),
        )

    parser.error("Missing command: create/detect")

    # try:
    #     project = RecCmpBuiltProject.from_directory(Path.cwd())
    # except RecCmpProjectException as e:
    #     parser.error(e.args[0])

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
