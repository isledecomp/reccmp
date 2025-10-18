import enum
import logging
from pathlib import Path
import shutil
import textwrap

from reccmp.assets import get_asset_file
from .config import (
    Hash,
    ProjectFile,
    ProjectFileTarget,
    UserFile,
    UserFileTarget,
)
from .common import RECCMP_PROJECT_CONFIG, RECCMP_USER_CONFIG, RECCMP_BUILD_CONFIG
from .detect import RecCmpProject, RecCmpPartialTarget, GhidraConfig
from .error import RecCmpProjectException
from .util import get_path_sha256, unique_targets


logger = logging.getLogger(__name__)


class RecCmpProjectAlreadyExistsError(RecCmpProjectException):
    def __init__(self, *_, path: Path | str | None = None, **__):
        super().__init__(f"Cannot overwrite existing project {path or ''}")


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
    """Generate template CMakeLists.txt file contents to build each target."""
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
    """Generate template C++ header for the given target."""
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
    """Generate a template C++ source file for the given target, depending on
    whether its file path is DLL or EXE. Includes sample reccmp annotations."""
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
    project_directory: Path,
    original_paths: list[Path],
    scm: bool = False,
    cmake: bool = False,
) -> RecCmpProject:
    """Generates reccmp-project.yml and reccmp-user.yml files in the given project directory.
    Requires a list of paths to original binaries that will be the focus of the decomp project.
    If `scm` is enabled, update an existing .gitignore to skip reccmp-user.yml and reccmp-build.yml files.
    If `cmake` is enabled, create CMakeLists.txt and generate sample source files to help get started.
    """

    # Intended reccmp-project.yml location
    project_config_path = project_directory / RECCMP_PROJECT_CONFIG

    # Don't overwrite an existing project
    if project_config_path.exists():
        raise RecCmpProjectAlreadyExistsError(path=project_config_path)

    if not original_paths:
        raise RecCmpProjectException("Need at least one original binary")

    for original_path in original_paths:
        if not original_path.is_file():
            raise FileNotFoundError(f"Original binary ({original_path}) is not a file")

    # reccmp-user.yml location
    user_config_path = project_directory / RECCMP_USER_CONFIG

    # Use the base name for each original binary to create a unique ID.
    # If any base names are non-unique, add a number.
    targets = dict(unique_targets(original_paths))

    # Object to serialize to YAML
    project_config_data = ProjectFile(targets={})

    # Return object for user
    project = RecCmpProject(project_config_path=project_config_path)

    # Populate targets for each project object
    for target_id, original_path in targets.items():
        # Calculate SHA256 checksum of the original binary. reccmp will verify this
        # at startup to make sure each contributor is working with the same file.
        hash_sha256 = get_path_sha256(original_path)

        # The project file uses the base filename only. The path to the binary file
        # is in the user file because it is different for each contributor.
        target_filename = original_path.name

        project_config_data.targets[target_id] = ProjectFileTarget(
            filename=target_filename,
            source_root=Path("."),
            hash=Hash(sha256=hash_sha256),
        )

        project.targets[target_id] = RecCmpPartialTarget(
            target_id=target_id,
            filename=target_filename,
            sha256=hash_sha256,
            source_root=Path("."),
            ghidra_config=GhidraConfig(),
        )

    # Write project YAML file
    logger.debug("Creating %s...", project_config_path)
    project_config_data.write_file(project_config_path)

    # The user YAML file has the path to the original binary for each target
    user_config_data = UserFile(
        targets={
            uid: UserFileTarget(path=path.resolve()) for uid, path in targets.items()
        }
    )

    # Write user YAML file
    logger.debug("Creating %s...", user_config_path)
    user_config_data.write_file(user_config_path)

    if scm:
        # Update existing .gitignore to skip reccmp-build.yml and reccmp-user.yml.
        gitignore_path = project_directory / ".gitignore"
        if not gitignore_path.exists():
            gitignore_path.touch()

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
        # Generate tempalte files so you can start building each target with CMake.
        project_cmake_dir = project_directory / "cmake"
        project_cmake_dir.mkdir(exist_ok=True)

        # Copy template CMake script that generates reccmp-build.yml
        logger.debug("Copying %s...", "cmake/reccmp.cmake")
        shutil.copy(
            get_asset_file("cmake/reccmp.cmake"),
            project_directory / "cmake/reccmp.cmake",
        )

        # Use first target ID as cmake project name
        project_name = next(iter(targets.keys()), "NEW_DECOMP_PROJECT")
        cmakelists_txt = get_default_cmakelists_txt(
            project_name=project_name, targets=targets
        )

        # Create CMakeLists.txt
        cmakelists_path = project_directory / "CMakeLists.txt"
        logger.debug("Creating %s...", cmakelists_path)
        with cmakelists_path.open("w") as f:
            f.write(cmakelists_txt)

        # Create template C++ source and header file for each target.
        for target_id, original_path in targets.items():
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
