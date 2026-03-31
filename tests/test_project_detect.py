"""Tests for the detect_project() function, the main part of the reccmp-project utility."""

import textwrap

from reccmp.project.common import (
    RECCMP_BUILD_CONFIG,
    RECCMP_PROJECT_CONFIG,
    RECCMP_USER_CONFIG,
)
from reccmp.project.config import (
    BuildFile,
    UserFile,
)
from reccmp.project.detect import (
    detect_project,
    DetectWhat,
)
from reccmp.formats import PEImage

LEGO1_SHA256 = "14645225bbe81212e9bc1919cd8a692b81b8622abb6561280d99b0fc4151ce17"


def helper_create_project(target_name: str, filename: str, sha256: str) -> str:
    """Creates YML for a project file with one target using the given parameters."""
    return textwrap.dedent(f"""\
    targets:
      {target_name}:
        filename: {filename}
        source-root: sources
        hash:
          sha256: {sha256}
    """)


def test_project_original_detection_miss(tmp_path_factory):
    """Test `reccmp-project detect --what original --search-path <dir>` without success"""
    project_text = helper_create_project("LEGO1", "LEGO1.DLL", LEGO1_SHA256)
    project_root = tmp_path_factory.mktemp("project")
    (project_root / RECCMP_PROJECT_CONFIG).write_text(project_text)
    detect_project(
        project_directory=project_root,
        search_path=[project_root],
        detect_what=DetectWhat.ORIGINAL,
    )
    user_config_path = project_root / RECCMP_USER_CONFIG
    # User config file created regardless
    assert user_config_path.is_file()
    user_config = UserFile.from_file(user_config_path)
    assert "LEGO1" not in user_config.targets


def test_project_original_detection_using_path(tmp_path_factory, binfile: PEImage):
    """Test `reccmp-project detect --what original --search-path <dir>`"""
    project_text = helper_create_project("LEGO1", "LEGO1.DLL", LEGO1_SHA256)
    project_root = tmp_path_factory.mktemp("project")
    (project_root / RECCMP_PROJECT_CONFIG).write_text(project_text)
    bin_path = binfile.filepath
    detect_project(
        project_directory=project_root,
        search_path=[bin_path.parent],
        detect_what=DetectWhat.ORIGINAL,
    )
    user_config_path = project_root / RECCMP_USER_CONFIG
    assert user_config_path.is_file()
    user_config = UserFile.from_file(user_config_path)
    assert user_config.targets["LEGO1"].path == bin_path


def test_project_original_detection_using_file(tmp_path_factory, binfile: PEImage):
    """Test `reccmp-project detect --what original --search-path <file>`"""
    project_text = helper_create_project("LEGO1", "LEGO1.DLL", LEGO1_SHA256)
    project_root = tmp_path_factory.mktemp("project")
    (project_root / RECCMP_PROJECT_CONFIG).write_text(project_text)
    bin_path = binfile.filepath
    detect_project(
        project_directory=project_root,
        search_path=[bin_path],
        detect_what=DetectWhat.ORIGINAL,
    )
    user_config_path = project_root / RECCMP_USER_CONFIG
    assert user_config_path.is_file()
    user_config = UserFile.from_file(user_config_path)
    assert user_config.targets["LEGO1"].path == bin_path


def test_project_original_detection_using_alternate_filename(
    tmp_path_factory, binfile: PEImage
):
    """Test `reccmp-project detect --what original --search-path <file>`
    The project filename does not match the input search path filename.
    However, we can still verify the file's hash and accept it as the original path.
    """
    project_text = helper_create_project("LEGO1", "GAME.dll", LEGO1_SHA256)
    project_root = tmp_path_factory.mktemp("project")
    (project_root / RECCMP_PROJECT_CONFIG).write_text(project_text)
    bin_path = binfile.filepath
    detect_project(
        project_directory=project_root,
        search_path=[bin_path],
        detect_what=DetectWhat.ORIGINAL,
    )
    user_config_path = project_root / RECCMP_USER_CONFIG
    assert user_config_path.is_file()
    user_config = UserFile.from_file(user_config_path)
    assert user_config.targets["LEGO1"].path == bin_path


def test_project_recompiled_detection_miss(tmp_path_factory):
    """Test `reccmp-project detect --what recompiled --search-path <dir>` without success"""
    project_text = helper_create_project("LEGO1", "LEGO1.DLL", LEGO1_SHA256)
    project_root = tmp_path_factory.mktemp("project")
    (project_root / RECCMP_PROJECT_CONFIG).write_text(project_text)

    detect_project(
        project_directory=project_root,
        search_path=[project_root],
        detect_what=DetectWhat.RECOMPILED,
        build_directory=project_root,
    )
    build_config_path = project_root / RECCMP_BUILD_CONFIG
    # Build file created regardless
    assert build_config_path.is_file()
    build_config = BuildFile.from_file(build_config_path)
    assert "LEGO1" not in build_config.targets


def test_project_recompiled_detection_incomplete(tmp_path_factory):
    """Test `reccmp-project detect --what recompiled --search-path <dir>`
    Fail if we do not find a pdb in the same location with the same base name."""
    project_text = helper_create_project("LEGO1", "LEGO1.DLL", LEGO1_SHA256)
    project_root = tmp_path_factory.mktemp("project")
    (project_root / RECCMP_PROJECT_CONFIG).write_text(project_text)

    build_dir = project_root / "build"
    build_dir.mkdir()

    build_file = build_dir / "LEGO1.DLL"
    build_file.write_text("")

    detect_project(
        project_directory=project_root,
        search_path=[build_dir],
        detect_what=DetectWhat.RECOMPILED,
        build_directory=project_root,
    )
    build_config_path = project_root / RECCMP_BUILD_CONFIG
    assert build_config_path.is_file()
    build_config = BuildFile.from_file(build_config_path)
    # Does not create partial build target
    assert "LEGO1" not in build_config.targets


def test_project_recompiled_detection_using_path(tmp_path_factory):
    """Test `reccmp-project detect --what recompiled --search-path <dir>`"""
    project_text = helper_create_project("LEGO1", "LEGO1.DLL", LEGO1_SHA256)
    project_root = tmp_path_factory.mktemp("project")
    (project_root / RECCMP_PROJECT_CONFIG).write_text(project_text)

    build_dir = project_root / "build"
    build_dir.mkdir()

    build_file = build_dir / "LEGO1.DLL"
    build_file.write_text("")

    pdb_file = build_file.with_suffix(".pdb")
    pdb_file.write_text("")

    detect_project(
        project_directory=project_root,
        search_path=[build_dir],
        detect_what=DetectWhat.RECOMPILED,
        build_directory=project_root,
    )
    build_config_path = project_root / RECCMP_BUILD_CONFIG
    assert build_config_path.is_file()
    build_config = BuildFile.from_file(build_config_path)
    assert build_config.targets["LEGO1"].path == build_file
    assert build_config.targets["LEGO1"].pdb == pdb_file


def test_project_recompiled_detection_using_file(tmp_path_factory):
    """Test `reccmp-project detect --what recompiled --search-path <file>`"""
    project_text = helper_create_project("LEGO1", "LEGO1.DLL", LEGO1_SHA256)
    project_root = tmp_path_factory.mktemp("project")
    (project_root / RECCMP_PROJECT_CONFIG).write_text(project_text)

    build_dir = project_root / "build"
    build_dir.mkdir()

    build_file = build_dir / "LEGO1.DLL"
    build_file.write_text("")

    pdb_file = build_file.with_suffix(".pdb")
    pdb_file.write_text("")

    detect_project(
        project_directory=project_root,
        search_path=[build_file],
        detect_what=DetectWhat.RECOMPILED,
        build_directory=project_root,
    )
    build_config_path = project_root / RECCMP_BUILD_CONFIG
    assert build_config_path.is_file()
    build_config = BuildFile.from_file(build_config_path)
    assert build_config.targets["LEGO1"].path == build_file
    assert build_config.targets["LEGO1"].pdb == pdb_file


def test_project_recompiled_detection_using_alternate_filename(tmp_path_factory):
    """Test `reccmp-project detect --what recompiled --search-path <file>`
    The project filename does not match the input search path filename.
    We do not have a checksum to match against, so use the first file that exists."""
    project_text = helper_create_project("LEGO1", "HELLO.DLL", LEGO1_SHA256)
    project_root = tmp_path_factory.mktemp("project")
    (project_root / RECCMP_PROJECT_CONFIG).write_text(project_text)

    build_dir = project_root / "build"
    build_dir.mkdir()

    build_file = build_dir / "LEGO1.DLL"
    build_file.write_text("")

    pdb_file = build_file.with_suffix(".pdb")
    pdb_file.write_text("")

    detect_project(
        project_directory=project_root,
        # Search a non-existent path first.
        search_path=[project_root / "dummy.dll", build_file],
        detect_what=DetectWhat.RECOMPILED,
        build_directory=project_root,
    )
    build_config_path = project_root / RECCMP_BUILD_CONFIG
    assert build_config_path.is_file()
    build_config = BuildFile.from_file(build_config_path)
    assert build_config.targets["LEGO1"].path == build_file
    assert build_config.targets["LEGO1"].pdb == pdb_file
