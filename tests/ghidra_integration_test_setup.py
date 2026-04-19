from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, cast
from unittest.mock import Mock
import pytest

from pyghidra import HeadlessPyGhidraLauncher  # type: ignore[import-untyped]

from reccmp.compare.core import Compare
from reccmp.compare.ingest import load_cvdump_types
from reccmp.cvdump.analysis import CvdumpAnalysis
from reccmp.cvdump.parser import CvdumpParser
from .raw_image import RawImage

# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

if TYPE_CHECKING:
    from ghidra.program.model.listing import Program
    from ghidra.program.flatapi import FlatProgramAPI
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter

GHIDRA_PROJECT_NAME = "ghidra-integration-test"
GHIDRA_FOLDER_NAME = "/"
GHIDRA_PROGRAM_NAME = "ISLE.EXE"


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
    request: pytest.FixtureRequest, isle_binary_path: Path
) -> "Iterator[Program]":
    assert request.config.cache is not None

    try:
        # Gets rid of spurious stack traces from a misunderstanding between pytest and jpype.
        # See https://jpype.readthedocs.io/en/latest/userguide.html#errors-reported-by-python-fault-handler
        import faulthandler

        faulthandler.enable()
        faulthandler.disable()
    # pylint: disable-next=broad-exception-caught # This is fine to fail, we don't need to handle it
    except Exception:
        pass

    HeadlessPyGhidraLauncher().start()

    # pylint: disable-next=import-error
    from java.lang import Object  # type: ignore[import-not-found]
    from ghidra.app.util.importer import ProgramLoader
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.base.project import GhidraProject
    from ghidra.program.model.address import AddressSetView
    from ghidra.program.model.listing import Program
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.util.task import TaskMonitor

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
            dom_file = project.getProjectData().getFile(
                f"{GHIDRA_FOLDER_NAME}{GHIDRA_PROGRAM_NAME}"
            )

            # The object responsible for releasing `program`
            consumer = Object()
            ok_to_upgrade = True  # not sure if this matters
            ok_to_recover = False  # not sure if this matters
            ghidra_program = dom_file.getDomainObject(
                consumer, ok_to_upgrade, ok_to_recover, TaskMonitor.DUMMY
            )
            assert isinstance(ghidra_program, Program)

            yield ghidra_program

    # pylint: disable-next=broad-exception-caught # We cannot control all the exceptions that can be raised here
    except Exception as e:
        print(e)
        print(f"Failed to load a cached Ghidra test project: {e}")
        print("Creating a new Ghidra test project...")

        ghidra_project = GhidraProject.createProject(
            str(project_dir), GHIDRA_PROJECT_NAME, False
        )
        try:
            project = ghidra_project.getProject()

            # The object responsible for releasing `program`
            consumer = Object()
            ghidra_program = (
                ProgramLoader.builder()
                .source(str(isle_binary_path))
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
                    # Nullability is not encoded in the headers
                    cast(AddressSetView, None)
                )
                mgr.startAnalysis(TaskMonitor.DUMMY)
                GhidraProgramUtilities.markProgramAnalyzed(ghidra_program)
                transaction.commit()

            # Save the file to the project in order to accelerate the next startup.
            # Don't use ghidra_project.saveAs(), it creates a transaction by default.
            folder = ghidra_project.getProjectData().getFolder(GHIDRA_FOLDER_NAME)
            assert folder is not None
            folder.createFile(GHIDRA_PROGRAM_NAME, ghidra_program, TaskMonitor.DUMMY)

            yield ghidra_program

        finally:
            ghidra_project.getProject().close()


class GhidraTypeTestHelper:
    def __init__(self, ghidra: "FlatProgramAPI"):
        from reccmp.ghidra.importer.type_importer import (
            PdbTypeImporter,
            PdbFunctionExtractor,
        )

        self.ghidra = ghidra
        self.compare = Compare(
            RawImage.from_memory(), RawImage.from_memory(), Mock(), "TEST"
        )
        self.type_importer = PdbTypeImporter(
            ghidra, PdbFunctionExtractor(self.compare), set()
        )

    def set_up_cvdump_types(self, cvdump_types: str):
        parser = CvdumpParser()
        parser.read_section("TYPES", cvdump_types)
        analysis = CvdumpAnalysis(parser)
        load_cvdump_types(analysis, self.compare.types)


class GhidraFunctionTestHelper:
    ORIG_FN_TO_OVERWRITE_PRIMARY = 0x00402880  # readIntFromRegistry()
    ORIG_FN_TO_OVERWRITE_SECONDARY = 0x00402C20  # IsleApp::Tick()
    ORIG_DATA_TO_OVERWRITE = 0x00410040 # g_windowRect

    def __init__(self, ghidra: "FlatProgramAPI"):
        self.ghidra = ghidra
        self.orig_address = self.ORIG_FN_TO_OVERWRITE_PRIMARY
        self.address_ghidra = ghidra.getAddressFactory().getAddress(
            hex(self.orig_address)
        )
        self.ghidra_function = self.ghidra.getFunctionContaining(self.address_ghidra)
        assert (
            self.ghidra_function is not None
        ), f"No Ghidra function at address {self.address_ghidra}"

    def overwrite_example_function(self, data: bytes):
        from jpype import JArray, JByte  # type: ignore[import-untyped]

        assert len(data) > 0

        # Clear the existing decompiled code so we can overwrite it
        listing = self.ghidra.getCurrentProgram().getListing()
        end_addr = self.address_ghidra.add(len(data) - 1)
        listing.clearCodeUnits(self.address_ghidra, end_addr, False)

        # Overwrite the memory
        self.ghidra.getCurrentProgram().getMemory().setBytes(
            self.address_ghidra, JArray.of(data, JByte)
        )

    def assert_c_code(self, code: str):
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import TaskMonitor

        iface = DecompInterface()
        iface.openProgram(self.ghidra.getCurrentProgram())

        res = iface.decompileFunction(self.ghidra_function, 5, TaskMonitor.DUMMY)
        assert res.decompileCompleted(), "Decompilation failed"

        # The line endings returned by the API differ between Windows and Linux
        decompiled_c_code = res.getDecompiledFunction().getC().replace("\r\n", "\n")

        # This print statement is suppressed when the test passes, but is helpful if the test fails
        print(decompiled_c_code)

        assert decompiled_c_code == code
