from pathlib import Path
import textwrap

import reccmp.project.detect


def test_project_detection(tmp_path_factory, binfile):
    project_root = tmp_path_factory.getbasetemp()
    build_path = tmp_path_factory.mktemp("build")
    (project_root / "reccmp-project.yml").write_text(
        textwrap.dedent(
            """\
            targets:
              LEGO1:
                filename: LEGO1.dll
                source-root: sources
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
    project = reccmp.project.detect.RecCmpProject.from_directory(project_root)
    assert len(project.targets) == 1
    assert "LEGO1" in project.targets
    assert project.targets["LEGO1"].target_id == "LEGO1"
    assert project.targets["LEGO1"].filename == "LEGO1.dll"
    assert project.targets["LEGO1"].source_root == project_root / "sources"

    built_project = reccmp.project.detect.RecCmpBuiltProject.from_directory(build_path)
    assert len(built_project.targets) == 1
    assert built_project.targets["LEGO1"].filename == "LEGO1.dll"
    assert built_project.targets["LEGO1"].source_root == project_root / "sources"
    assert built_project.targets["LEGO1"].original_path == Path(binfile.filename)
    assert built_project.targets["LEGO1"].recompiled_path == recompiled_lib
    assert built_project.targets["LEGO1"].recompiled_pdb == recompiled_pdb
