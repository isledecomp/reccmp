# TODO:
# - decide on a binary
#   - maybe a current recompiled `ISLE.EXE`?
# - make work locally
#   - Consider saving project to repository

# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

# def test_ghidra_experiment(ghidra):
from pathlib import Path
import shutil
from unittest.mock import Mock

from pyghidra import HeadlessPyGhidraLauncher

from reccmp.cvdump.cvinfo import CVInfoTypeEnum


def test_ghidra_experiment(tmp_path):
    source_dir = Path(__file__).parent / "ghidra"
    project_dir = tmp_path
    shutil.copytree(source_dir, project_dir, dirs_exist_ok=True)

    HeadlessPyGhidraLauncher().start()

    from ghidra.program.flatapi import FlatProgramAPI
    from reccmp.ghidra.importer.context import open_ghidra_project
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter

    print("Ghidra started")


    with open_ghidra_project(
        str(project_dir), "integration-test", restore_project=False
    ) as project:
        read_only = False
        program = project.openProgram("/", "ISLE.EXE", read_only)
        api = FlatProgramAPI(program)


        type_importer = PdbTypeImporter(api, Mock(), set())

        int4 = type_importer.import_pdb_type_into_ghidra(CVInfoTypeEnum.T_INT4)

        assert int4.length == 4

    # assert False
