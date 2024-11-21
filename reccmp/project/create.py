import enum
import itertools
import logging
from pathlib import Path
import shutil
import textwrap

import ruamel.yaml

from reccmp.assets import get_asset_file
from .config import (
    GhidraConfig,
    Hash,
    ProjectFile,
    ProjectFileTarget,
    UserFile,
    UserFileTarget,
)
from .common import RECCMP_PROJECT_CONFIG, RECCMP_USER_CONFIG, RECCMP_BUILD_CONFIG
from .detect import RecCmpProject, RecCmpTarget
from .error import RecCmpProjectException
from .util import get_path_sha256, path_to_id


logger = logging.getLogger(__name__)


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
    raise RecCmpProjectException("Unknown target type")


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
                f"""\
                #ifdef _WIN32
                #include <windows.h>

                // FUNCTION: {target_id} 0x10000020
                int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, int nCmdShow) {{
                    return 0;
                }}
                #else
                // FUNCTION: {target_id} 0x10000020
                int main(int argc, char *argv[]) {{
                    return 0;
                }}
                #endif
            """
            )
        case TargetType.SHARED_LIBRARY:
            entry_function = textwrap.dedent(
                f"""\
                #ifdef _WIN32
                #include <windows.h>

                // FUNCTION: {target_id} 0x10000020
                BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved ) {{
                    return TRUE;
                }}
                #endif
            """
            )
    return (
        textwrap.dedent(
            f"""\
        #include "{hpp_path.name}"

        // FUNCTION: {target_id} 0x10000000
        SomeClass::~SomeClass() {{
        }}

        // GLOBAL: {target_id} 0x10102000
        // STRING: {target_id} 0x10101f00
        const char* g_globalString = "A global string";
    """
        )
        + "\n"
        + entry_function
    )


def create_project(
    project_directory: Path, original_paths: list[Path], scm: bool, cmake: bool
) -> RecCmpProject:
    if not original_paths:
        raise RecCmpProjectException("Need at least one original binary")
    id_path: dict[str, Path] = {}
    project_config_data = ProjectFile(targets={})
    project_config_path = project_directory / RECCMP_PROJECT_CONFIG
    user_config_path = project_directory / RECCMP_USER_CONFIG
    project = RecCmpProject(project_config_path=project_config_path)
    for original_path in original_paths:
        if not original_path.is_file():
            raise RecCmpProjectException(
                f"Original binary ({original_path}) is not a file"
            )
        target_id = path_to_id(original_path)
        hash_sha256 = get_path_sha256(original_path)
        target_filename = original_path.name
        target_data = ProjectFileTarget(
            filename=target_filename,
            source_root=project_directory,
            hash=Hash(sha256=hash_sha256),
        )
        if target_id in project_config_data.targets:
            for suffix_nb in itertools.count(start=0, step=1):
                new_target_id = f"{target_id}_{suffix_nb}"
                if new_target_id not in project_config_data.targets:
                    target_id = new_target_id
                    break
        project_config_data.targets[target_id] = target_data
        id_path[target_id] = original_path
        project.targets[target_id] = RecCmpTarget(
            target_id=target_id,
            filename=target_filename,
            source_root=project_directory,
            ghidra_config=GhidraConfig.default(),
        )

    if project_config_path.exists():
        raise RecCmpProjectException(
            f"Failed to create a new reccmp project: there already exists one: {project_config_path}"
        )

    project_name = path_to_id(original_paths[0])
    logger.debug("Creating %s...", project_config_path)
    with project_config_path.open("w") as f:
        yaml = ruamel.yaml.YAML()
        yaml.dump(data=project_config_data.model_dump(mode="json"), stream=f)

    user_config_data = UserFile(
        targets={
            uid: UserFileTarget(path=path.resolve()) for uid, path in id_path.items()
        }
    )

    logger.debug("Creating %s...", user_config_data)
    with user_config_path.open("w") as f:
        yaml = ruamel.yaml.YAML()
        yaml.dump(data=user_config_data.model_dump(mode="json"), stream=f)

    if scm:
        gitignore_path = project_directory / ".gitignore"
        if gitignore_path.exists():
            ignore_rules = gitignore_path.read_text().splitlines()
            if RECCMP_USER_CONFIG not in ignore_rules:
                logger.debug("Adding '%s' to .gitignore...", RECCMP_USER_CONFIG)
                with gitignore_path.open("a") as f:
                    f.write(f"{RECCMP_USER_CONFIG}\n")
            if RECCMP_BUILD_CONFIG not in ignore_rules:
                logger.debug("Adding '%s' to .gitignore...", RECCMP_BUILD_CONFIG)
                with gitignore_path.open("a") as f:
                    f.write(f"{RECCMP_BUILD_CONFIG}\n")

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
    return project
