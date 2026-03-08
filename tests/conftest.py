from contextlib import contextmanager
import hashlib
from pathlib import Path
from typing import Callable, Iterator, TYPE_CHECKING
import pytest
from pyghidra import HeadlessPyGhidraLauncher  # type: ignore[import-untyped]

from reccmp.formats import NEImage, PEImage, detect_image

# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false


if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Program


def pytest_addoption(parser):
    """Allow the option to run tests against sample binaries."""
    parser.addoption("--binfiles", action="store", help="Path to sample binary files.")
    parser.addoption(
        "--require-binfiles",
        action="store_true",
        help="Fail tests that depend on binary samples if we cannot load them.",
    )
    parser.addoption(
        "--require-ghidra",
        action="store_true",
        help="Fail tests that depend on Ghidra it is not available.",
    )


def check_hash(path: Path, hash_str: str) -> bool:
    with path.open("rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
        return digest == hash_str


# SkiFree 1.0
# https://ski.ihoc.net/
SKI_SHA256 = "0b97b99fcf34af5f5d624080417c79c7d36ae11351a7870ce6e0a476f03515c2"


@pytest.fixture(name="bin_loader", scope="session")
def fixture_loader(pytestconfig) -> Iterator[Callable[[str, str], Path]]:
    # Search path is ./tests/binfiles unless the user provided an alternate location.
    binfiles_arg = pytestconfig.getoption("--binfiles")
    if binfiles_arg is not None:
        binfile_path = Path(binfiles_arg).resolve()
    else:
        binfile_path = Path(__file__).resolve().parent / "binfiles"

    def loader(filename: str, hash_str: str) -> Path:
        file = binfile_path / filename
        if file.exists():
            if not check_hash(file, hash_str):
                pytest.fail(
                    pytrace=False, reason="Did not match expected " + filename.upper()
                )

            return file

        not_found_reason = "No path to " + filename.upper()
        if pytestconfig.getoption("--require-binfiles"):
            pytest.fail(pytrace=False, reason=not_found_reason)

        pytest.skip(allow_module_level=True, reason=not_found_reason)

    yield loader


LEGO1_SHA256 = "14645225bbe81212e9bc1919cd8a692b81b8622abb6561280d99b0fc4151ce17"


@pytest.fixture(name="binfile", scope="session")
def fixture_binfile(bin_loader: Callable[[str, str], Path]) -> Iterator[PEImage]:
    """LEGO1.DLL: v1.1 English, September"""
    image = detect_image(
        bin_loader(
            "LEGO1.DLL",
            LEGO1_SHA256,
        )
    )
    assert isinstance(image, PEImage)
    yield image


SKI_SHA256 = "0b97b99fcf34af5f5d624080417c79c7d36ae11351a7870ce6e0a476f03515c2"


@pytest.fixture(name="skifree", scope="session")
def fixture_skifree(bin_loader: Callable[[str, str], Path]) -> Iterator[NEImage]:
    """SkiFree 1.0
    https://ski.ihoc.net/"""
    image = detect_image(
        bin_loader(
            "SKI.EXE",
            SKI_SHA256,
        )
    )
    assert isinstance(image, NEImage)
    yield image


GHIDRA_PROJECT_NAME = "ghidra-integration-test"
ISLE_SHA256 = "5cf57c284973fce9d14f5677a2e4435fd989c5e938970764d00c8932ed5128ca"


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



@pytest.fixture(name="ghidra_program", scope="session")
def fixture_ghidra_loader(
    pytestconfig, request: pytest.FixtureRequest, bin_loader: Callable[[str, str], Path]
) -> "Iterator[FlatProgramAPI]":
    assert request.config.cache is not None

    try:
        HeadlessPyGhidraLauncher().start()

        # pylint: disable-next=import-error
        from java.lang import Object  # type: ignore[import-not-found]
        from ghidra.util.task import TaskMonitor
        from ghidra.base.project import GhidraProject
        from ghidra.app.util.importer import ProgramLoader
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        from ghidra.program.util import GhidraProgramUtilities
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

            # In case this file is not available, a `pytest.OutcomeException` is raised.
            # Then we drop into the `except` below, where we skip or fail depending
            # on whether `--require-ghidra` is set.
            bin_file_path = bin_loader(
                "ISLE.EXE",
                ISLE_SHA256,
            )

            ghidra_project = GhidraProject.createProject(
                str(project_dir), GHIDRA_PROJECT_NAME, False
            )
            project = ghidra_project.getProject()

            ghidra_program = (
                ProgramLoader.builder()
                .source(str(bin_file_path))
                .project(project)
                .load()
                .getPrimaryDomainObject()
            )

            with ghidra_bundle_host_reference():
                transaction = ghidra_program.openTransaction("test-project-setup-analysis")
                mgr = AutoAnalysisManager.getAnalysisManager(ghidra_program)
                mgr.initializeOptions()
                mgr.reAnalyzeAll(None)  # type: ignore -- Nullability is not encoded in the headers
                mgr.startAnalysis(TaskMonitor.DUMMY)
                GhidraProgramUtilities.markProgramAnalyzed(ghidra_program)
                transaction.commit()

            # Save the file to the project in order to accelerate the next startup.
            # Don't use ghidra_project.saveAs(), it creates a transaction by default.
            folder = ghidra_project.getProjectData().getFolder("/")
            assert folder is not None
            folder.createFile("ISLE.EXE", ghidra_program, TaskMonitor.DUMMY)

            yield ghidra_program

    # Need to catch a BaseException since that's what pytest's `OutcomeException` inherits from.
    # Unfortunately, that type is not exported. `except (Exception, pytest.OutcomeException)` would have been preferable.
    # pylint: disable-next=broad-exception-caught # We cannot control all the exceptions that can be raised here
    except BaseException as e:
        reason = f"Unable to start Ghidra: {e}"

        if pytestconfig.getoption("--require-ghidra"):
            pytest.fail(pytrace=False, reason=reason)

        pytest.skip(allow_module_level=True, reason=reason)


@pytest.fixture(name="ghidra", scope="function")
def fixture_ghidra(ghidra_program: "Program") -> "Iterator[FlatProgramAPI]":
    from ghidra.program.flatapi import FlatProgramAPI

    # The effect of `transaction.abort()` only becomes visible once all transactions are closed.
    # Therefore, lingering transactions can cause interference between tests.
    # If we want to be sure that the side effects of the tests we just ran have been reverted,
    # we need to make sure that no other transactions is already open.
    assert ghidra_program.getCurrentTransactionInfo() is None

    transaction = ghidra_program.openTransaction("reccmp-integration-test")
    api = FlatProgramAPI(ghidra_program)

    yield api

    # Revert all side effects of the test that just ran
    transaction.abort()
