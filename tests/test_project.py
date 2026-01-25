from pathlib import Path
import textwrap
import pytest

from reccmp.project.common import (
    RECCMP_BUILD_CONFIG,
    RECCMP_PROJECT_CONFIG,
    RECCMP_USER_CONFIG,
)
from reccmp.project.create import (
    create_project,
    RecCmpProjectAlreadyExistsError,
)
from reccmp.project.config import (
    ProjectFile,
    UserFile,
)
from reccmp.project.detect import detect_project, DetectWhat, RecCmpProject
from reccmp.project.error import (
    RecCmpProjectException,
    RecCmpProjectNotFoundException,
    InvalidRecCmpProjectException,
    IncompleteReccmpTargetError,
    UnknownRecCmpTargetException,
)
from reccmp.decomp.formats import PEImage


LEGO1_SHA256 = "14645225bbe81212e9bc1919cd8a692b81b8622abb6561280d99b0fc4151ce17"


def test_project_loading_no_files(tmp_path_factory):
    """Should fail to load a project if there are no files to load."""
    project_root = tmp_path_factory.mktemp("project")

    with pytest.raises(RecCmpProjectNotFoundException):
        RecCmpProject.from_directory(project_root)


def test_project_loading_project_only(tmp_path_factory):
    """Can load with a project.yml file only."""
    project_root = tmp_path_factory.mktemp("project")
    (project_root / RECCMP_PROJECT_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                filename: LEGO1.dll
                source-root: sources
                hash:
                  sha256: {LEGO1_SHA256}
            """
        )
    )

    project = RecCmpProject.from_directory(project_root)
    assert len(project.targets) == 1
    assert project.targets["LEGO1"].sha256 == LEGO1_SHA256
    assert project.targets["LEGO1"].source_root == project_root / "sources"
    assert project.project_config_path == project_root / RECCMP_PROJECT_CONFIG
    assert project.build_config_path is None
    assert project.user_config_path is None


def test_project_loading_project_and_user(tmp_path_factory):
    """Can load project.yml and combine with user.yml in the same directory."""
    project_root = tmp_path_factory.mktemp("project")
    (project_root / RECCMP_PROJECT_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                filename: LEGO1.dll
                source-root: sources
                hash:
                  sha256: {LEGO1_SHA256}
            """
        )
    )

    # does not need to exist in this test
    original_binary_path = Path("./binfiles/LEGO1.DLL")

    (project_root / RECCMP_USER_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                path: {original_binary_path}
            """
        )
    )

    project = RecCmpProject.from_directory(project_root)
    assert len(project.targets) == 1
    assert project.targets["LEGO1"].sha256 == LEGO1_SHA256
    assert project.targets["LEGO1"].source_root == project_root / "sources"
    assert project.targets["LEGO1"].original_path is not None
    assert (
        project.targets["LEGO1"].original_path.resolve()
        == project_root / original_binary_path
    )
    assert project.project_config_path == project_root / RECCMP_PROJECT_CONFIG
    assert project.user_config_path == project_root / RECCMP_USER_CONFIG


def test_project_loading_project_recursive_search(tmp_path_factory):
    """Can load project.yml even if we are in a subdirectory."""
    project_root = tmp_path_factory.mktemp("project")
    build_path = project_root / "build"
    build_path.mkdir()
    # Don't create the build file.

    (project_root / RECCMP_PROJECT_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                filename: LEGO1.dll
                source-root: sources
                hash:
                  sha256: {LEGO1_SHA256}
            """
        )
    )

    project = RecCmpProject.from_directory(build_path)
    assert project is not None
    assert project.project_config_path == project_root / RECCMP_PROJECT_CONFIG
    assert project.build_config_path is None


def test_project_loading_build_only(tmp_path_factory):
    """Should fail to load if our build.yml file points at a non-existent project file."""
    project_root = tmp_path_factory.mktemp("project")
    build_path = project_root / "build"
    build_path.mkdir()
    recompiled_lib = build_path / "LEGO1.dll"
    recompiled_pdb = build_path / "LEGO1.pdb"

    # Create only the build file to start. Project attribute points to a non-existent file.
    (build_path / RECCMP_BUILD_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            project: {project_root}
            targets:
              LEGO1:
                path: {recompiled_lib}
                pdb: {recompiled_pdb}
            """
        )
    )

    # Cannot finish loading: no project file
    with pytest.raises(InvalidRecCmpProjectException):
        RecCmpProject.from_directory(build_path)


def test_project_loading_build_and_project(tmp_path_factory):
    """Can load build.yml and matching project.yml."""
    project_root = tmp_path_factory.mktemp("project")
    build_path = project_root / "build"
    build_path.mkdir()
    # Use relative paths to validate that they are resolved relative to the `build.yaml`
    recompiled_lib = Path("LEGO1.dll")
    recompiled_pdb = Path("LEGO1.pdb")

    # Create only the build file to start. Project attribute points to a non-existent file.
    (build_path / RECCMP_BUILD_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            project: ..
            targets:
              LEGO1:
                path: {recompiled_lib}
                pdb: {recompiled_pdb}
            """
        )
    )

    # Now create the project file. We should be able to finish loading.
    (project_root / RECCMP_PROJECT_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                filename: LEGO1.dll
                source-root: sources
                hash:
                  sha256: {LEGO1_SHA256}
            """
        )
    )

    # Most properties are set for the target:
    project = RecCmpProject.from_directory(build_path)
    assert len(project.targets) == 1
    assert project.targets["LEGO1"].filename == "LEGO1.dll"
    assert project.targets["LEGO1"].source_root == project_root / "sources"
    assert project.targets["LEGO1"].recompiled_path == build_path / recompiled_lib
    assert project.targets["LEGO1"].recompiled_pdb == build_path / recompiled_pdb

    # but we are missing user data.
    assert project.targets["LEGO1"].original_path is None
    assert project.project_config_path == project_root / RECCMP_PROJECT_CONFIG
    assert project.build_config_path == build_path / RECCMP_BUILD_CONFIG


def test_project_loading_three_files(tmp_path_factory, binfile: PEImage):
    """Loading and combining data from all three files."""
    project_root = tmp_path_factory.mktemp("project")
    build_path = project_root / "build"
    build_path.mkdir()
    recompiled_lib = build_path / "LEGO1.dll"
    recompiled_pdb = build_path / "LEGO1.pdb"

    (build_path / RECCMP_BUILD_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            project: {project_root}
            targets:
              LEGO1:
                path: {recompiled_lib}
                pdb: {recompiled_pdb}
            """
        )
    )

    (project_root / RECCMP_PROJECT_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                filename: LEGO1.dll
                source-root: sources
                hash:
                  sha256: {LEGO1_SHA256}
            """
        )
    )

    (project_root / RECCMP_USER_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                path: {binfile.filepath}
            """
        )
    )

    project = RecCmpProject.from_directory(build_path)
    assert len(project.targets) == 1
    assert project.targets["LEGO1"].filename == "LEGO1.dll"
    assert project.targets["LEGO1"].source_root == project_root / "sources"
    assert project.targets["LEGO1"].original_path == binfile.filepath
    assert project.targets["LEGO1"].recompiled_path == recompiled_lib
    assert project.targets["LEGO1"].recompiled_pdb == recompiled_pdb

    # Confirm expected paths for the three files.
    assert project.project_config_path == project_root / RECCMP_PROJECT_CONFIG
    assert project.build_config_path == build_path / RECCMP_BUILD_CONFIG
    assert project.user_config_path == project_root / RECCMP_USER_CONFIG


def test_project_runtime_target(tmp_path_factory, binfile: PEImage):
    """Demonstrate that we cannot create a runtime target until we have complete information."""
    project_root = tmp_path_factory.mktemp("project")

    # Create project file first.
    (project_root / RECCMP_PROJECT_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                filename: LEGO1.dll
                source-root: sources
                hash:
                  sha256: {LEGO1_SHA256}
            """
        )
    )

    # We have an incomplete target with only the project data.
    project = RecCmpProject.from_directory(project_root)
    with pytest.raises(IncompleteReccmpTargetError):
        project.get("LEGO1")

    # Add the build file.
    build_path = project_root / "build"
    build_path.mkdir()
    recompiled_lib = build_path / "LEGO1.dll"
    recompiled_pdb = build_path / "LEGO1.pdb"
    (build_path / RECCMP_BUILD_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            project: {project_root}
            targets:
              LEGO1:
                path: {recompiled_lib}
                pdb: {recompiled_pdb}
            """
        )
    )

    # It is still incomplete without user data.
    project = RecCmpProject.from_directory(build_path)
    with pytest.raises(IncompleteReccmpTargetError):
        project.get("LEGO1")

    (project_root / RECCMP_USER_CONFIG).write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                path: {binfile.filepath}
            """
        )
    )

    project = RecCmpProject.from_directory(build_path)
    assert project.get("LEGO1") is not None

    # Cannot load non-existent target.
    with pytest.raises(UnknownRecCmpTargetException):
        project.get("TEST")


def test_project_original_detection(tmp_path_factory, binfile: PEImage):
    project_root = tmp_path_factory.mktemp("project")
    (project_root / "reccmp-project.yml").write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                filename: LEGO1.dll
                source-root: sources
                hash:
                  sha256: {LEGO1_SHA256}
            """
        )
    )
    bin_path = binfile.filepath
    detect_project(
        project_directory=project_root,
        search_path=[bin_path.parent],
        detect_what=DetectWhat.ORIGINAL,
    )
    assert (project_root / "reccmp-user.yml").is_file()


def test_project_creation(tmp_path_factory, binfile: PEImage):
    project_root = tmp_path_factory.mktemp("project")
    bin_path = Path(binfile.filepath)
    project_config_path = project_root / "reccmp-project.yml"
    user_config_path = project_root / "reccmp-user.yml"
    create_project(
        project_directory=project_root, original_paths=[bin_path], scm=True, cmake=True
    )
    assert project_config_path.is_file()
    assert user_config_path.is_file()
    target_name = bin_path.stem.upper()

    project = ProjectFile.from_file(project_config_path)
    assert len(project.targets) == 1
    assert target_name in project.targets
    assert project.targets[target_name].filename == bin_path.name

    # Must use relative paths in project file. Each contributor uses the same file.
    assert project.targets[target_name].source_root.is_absolute() is False

    # We assume the source root directory is the location of reccmp-project.yml.
    assert project_root / project.targets[target_name].source_root == project_root

    # Make sure the target list is established in reccmp-user.yml.
    user_config = UserFile.from_file(user_config_path)
    assert target_name in user_config.targets
    assert user_config.targets[target_name].path == bin_path

    # CMake and Git options enabled. Make sure we created the files.
    assert (project_root / ".gitignore").is_file()
    assert (project_root / "CMakeLists.txt").is_file()
    assert (project_root / "cmake/reccmp.cmake").is_file()


def test_create_overwrite_project_file(tmp_path_factory):
    """Do not overwrite an existing reccmp-project.yml file"""
    project_root = tmp_path_factory.mktemp("project")
    with (project_root / RECCMP_PROJECT_CONFIG).open("w+") as f:
        f.write("test")

    with pytest.raises(RecCmpProjectAlreadyExistsError):
        create_project(project_directory=project_root, original_paths=[])


def test_create_require_original_paths(tmp_path_factory):
    """Cannot create reccmp project without at least one original binary."""
    project_root = tmp_path_factory.mktemp("project")

    with pytest.raises(RecCmpProjectException):
        create_project(project_directory=project_root, original_paths=[])


def test_create_original_path_must_exist(tmp_path_factory):
    """Fail if any original binaries do not exist"""
    project_root = tmp_path_factory.mktemp("project")
    temp_dir = tmp_path_factory.mktemp("temp")

    with pytest.raises(FileNotFoundError):
        create_project(
            project_directory=project_root, original_paths=[temp_dir / "nonexist.dll"]
        )
