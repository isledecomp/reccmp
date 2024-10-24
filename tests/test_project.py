from pathlib import Path
import textwrap

from .conftest import LEGO1_SHA256
from reccmp.project.create import create_project, RecCmpProject
from reccmp.project.detect import detect_project, DetectWhat, RecCmpBuiltProject


def test_project_loading(tmp_path_factory, binfile):
    project_root = tmp_path_factory.mktemp("project")
    build_path = project_root / "build"
    build_path.mkdir()
    (project_root / "reccmp-project.yml").write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                filename: LEGO1.dll
                source-root: sources
                hashes:
                  sha256: {LEGO1_SHA256}
            """
        )
    )
    (project_root / "reccmp-user.yml").write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                path: {binfile.filename}
            """
        )
    )
    recompiled_lib = build_path / "LEGO1.dll"
    recompiled_pdb = build_path / "LEGO1.pdb"
    (build_path / "reccmp-build.yml").write_text(
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
    project = RecCmpProject.from_directory(project_root)
    assert len(project.targets) == 1
    assert "LEGO1" in project.targets
    assert project.targets["LEGO1"].target_id == "LEGO1"
    assert project.targets["LEGO1"].filename == "LEGO1.dll"
    assert project.targets["LEGO1"].source_root == project_root / "sources"

    built_project = RecCmpBuiltProject.from_directory(build_path)
    assert len(built_project.targets) == 1
    assert built_project.targets["LEGO1"].filename == "LEGO1.dll"
    assert built_project.targets["LEGO1"].source_root == project_root / "sources"
    assert built_project.targets["LEGO1"].original_path == Path(binfile.filename)
    assert built_project.targets["LEGO1"].recompiled_path == recompiled_lib
    assert built_project.targets["LEGO1"].recompiled_pdb == recompiled_pdb


def test_project_original_detection(tmp_path_factory, binfile):
    project_root = tmp_path_factory.mktemp("project")
    (project_root / "reccmp-project.yml").write_text(
        textwrap.dedent(
            f"""\
            targets:
              LEGO1:
                filename: LEGO1.dll
                source-root: sources
                hashes:
                  sha256: {LEGO1_SHA256}
            """
        )
    )
    bin_path = Path(binfile.filename)
    project = detect_project(
        project_directory=project_root,
        search_path=[bin_path.parent],
        detect_what=DetectWhat.ORIGINAL)
    assert (project_root / "reccmp-user.yml").is_file()



def test_project_creation(tmp_path_factory, binfile):
    project_root = tmp_path_factory.mktemp("project")
    bin_path = Path(binfile.filename)
    project_config_path = project_root / "reccmp-project.yml"
    user_config_path = project_root / "reccmp-user.yml"
    project = create_project(project_directory=project_root, original_paths=[bin_path], scm=True, cmake=True)
    assert project_config_path.is_file()
    assert user_config_path.is_file()
    target_name = bin_path.stem.upper()
    assert len(project.targets) == 1
    assert target_name in project.targets
    assert project.targets[target_name].target_id == target_name
    assert project.targets[target_name].filename == bin_path.name
    assert project.targets[target_name].source_root == project_root
    assert not (project_root / ".gitignore").is_file()
    assert (project_root / "CMakeLists.txt").is_file()
    assert (project_root / "cmake/reccmp.cmake").is_file()
