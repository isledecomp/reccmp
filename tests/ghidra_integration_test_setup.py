from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterator, cast


import pytest
from pyghidra import HeadlessPyGhidraLauncher  # type: ignore[import-untyped]

from .binfiles_test_setup import BINFILE_ISLE, TestBinfile


# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI

GHIDRA_PROJECT_NAME = "ghidra-integration-test"


@contextmanager
def ghidra_bundle_host_reference():
    """
    Ghidra's BundleHostReference is required to run Ghidra's analysis.
    It is crucial to release it again since Python does not terminate otherwise.
    """
    from ghidra.app.script import GhidraScriptUtil

    try:
        host_reference = GhidraScriptUtil.acquireBundleHostReference()
        yield host_reference
    finally:
        GhidraScriptUtil.releaseBundleHostReference()


def ghidra_integration_test_program(
    request: pytest.FixtureRequest, bin_loader: Callable[[TestBinfile], Path]
) -> "Iterator[FlatProgramAPI]":
    assert request.config.cache is not None

    HeadlessPyGhidraLauncher().start()

    # pylint: disable-next=import-error
    from java.lang import Object  # type: ignore[import-not-found]
    from ghidra.util.task import TaskMonitor
    from ghidra.base.project import GhidraProject
    from ghidra.app.util.importer import ProgramLoader
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.program.model.address import AddressSetView
    from reccmp.ghidra.importer.context import open_ghidra_project

    project_dir = request.config.cache.mkdir("ghidra_project")

    try:
        # Try to open a cached project setup (for performance)
        with open_ghidra_project(
            str(project_dir),
            GHIDRA_PROJECT_NAME,
            restore_project=False,
        ) as project:
            # Do not use `project.openProgram()`, it creates a transaction by default
            dom_file = project.getProjectData().getFile("/ISLE.EXE")

            # The object responsible for releasing `program`
            consumer = Object()
            ok_to_upgrade = True  # not sure if this matters
            ok_to_recover = False  # not sure if this matters
            ghidra_program = dom_file.getDomainObject(
                consumer, ok_to_upgrade, ok_to_recover, TaskMonitor.DUMMY
            )

            yield ghidra_program

    # pylint: disable-next=broad-exception-caught # We cannot control all the exceptions that can be raised here
    except Exception as e:
        print(e)
        print(f"Failed to load a cached Ghidra test project: {e}")
        print("Creating a new Ghidra test project...")

        bin_file_path = bin_loader(BINFILE_ISLE)

        ghidra_project = GhidraProject.createProject(
            str(project_dir), GHIDRA_PROJECT_NAME, False
        )
        try:
            project = ghidra_project.getProject()

            # The object responsible for releasing `program`
            consumer = Object()
            ghidra_program = (
                ProgramLoader.builder()
                .source(str(bin_file_path))
                .project(project)
                .load()
                .getPrimaryDomainObject(consumer)
            )

            with ghidra_bundle_host_reference():
                transaction = ghidra_program.openTransaction(
                    "test-project-setup-analysis"
                )
                mgr = AutoAnalysisManager.getAnalysisManager(ghidra_program)
                mgr.initializeOptions()
                mgr.reAnalyzeAll(
                    cast(AddressSetView, None)
                )  # Nullability is not encoded in the headers
                mgr.startAnalysis(TaskMonitor.DUMMY)
                GhidraProgramUtilities.markProgramAnalyzed(ghidra_program)
                transaction.commit()

            # Save the file to the project in order to accelerate the next startup.
            # Don't use ghidra_project.saveAs(), it creates a transaction by default.
            folder = ghidra_project.getProjectData().getFolder("/")
            assert folder is not None
            folder.createFile("ISLE.EXE", ghidra_program, TaskMonitor.DUMMY)

            yield ghidra_program

        finally:
            ghidra_project.getProject().close()
