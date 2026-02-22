import hashlib
from pathlib import Path
from typing import Callable, Iterator, TYPE_CHECKING
import shutil
import pytest
from pyghidra import HeadlessPyGhidraLauncher

from reccmp.formats import Image, NEImage, PEImage, detect_image

# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false


if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI


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
def fixture_loader(pytestconfig) -> Iterator[Callable[[str, str], Image | None]]:
    # Search path is ./tests/binfiles unless the user provided an alternate location.
    binfiles_arg = pytestconfig.getoption("--binfiles")
    if binfiles_arg is not None:
        binfile_path = Path(binfiles_arg).resolve()
    else:
        binfile_path = Path(__file__).resolve().parent / "binfiles"

    def loader(filename: str, hash_str: str) -> Image | None:
        file = binfile_path / filename
        if file.exists():
            if not check_hash(file, hash_str):
                pytest.fail(
                    pytrace=False, reason="Did not match expected " + filename.upper()
                )

            return detect_image(file)

        not_found_reason = "No path to " + filename.upper()
        if pytestconfig.getoption("--require-binfiles"):
            pytest.fail(pytrace=False, reason=not_found_reason)

        pytest.skip(allow_module_level=True, reason=not_found_reason)

        return None

    yield loader


@pytest.fixture(name="binfile", scope="session")
def fixture_binfile(bin_loader) -> Iterator[PEImage]:
    """LEGO1.DLL: v1.1 English, September"""
    image = bin_loader(
        "LEGO1.DLL", "14645225bbe81212e9bc1919cd8a692b81b8622abb6561280d99b0fc4151ce17"
    )
    assert isinstance(image, PEImage)
    yield image


@pytest.fixture(name="skifree", scope="session")
def fixture_skifree(bin_loader) -> Iterator[NEImage]:
    """SkiFree 1.0
    https://ski.ihoc.net/"""
    image = bin_loader(
        "SKI.EXE", "0b97b99fcf34af5f5d624080417c79c7d36ae11351a7870ce6e0a476f03515c2"
    )
    assert isinstance(image, NEImage)
    yield image


@pytest.fixture(name="ghidra_loader", scope="session")
def fixture_ghidra_loader(pytestconfig, tmp_path_factory) -> "Iterator[FlatProgramAPI]":
    try:
        source_dir = Path(__file__).parent / "ghidra"
        project_dir = tmp_path_factory.mktemp("ghidra")
        shutil.copytree(source_dir, project_dir, dirs_exist_ok=True)

        HeadlessPyGhidraLauncher().start()

        from ghidra.program.flatapi import FlatProgramAPI
        from reccmp.ghidra.importer.context import open_ghidra_project

        print("Ghidra started")

        with open_ghidra_project(
            str(project_dir), "integration-test", restore_project=False
        ) as project:
            read_only = False
            program = project.openProgram("/", "ISLE.EXE", read_only)
            api = FlatProgramAPI(program)

            yield api

    # pylint: disable=broad-exception-caught # We cannot control all the exceptions that can be raised here
    except Exception as e:
        reason = f"Unable to start Ghidra: {e}"

        if pytestconfig.getoption("--require-ghidra"):
            pytest.fail(pytrace=False, reason=reason)

        pytest.skip(allow_module_level=True, reason=reason)


@pytest.fixture(name="ghidra", scope="function")
def fixture_ghidra(ghidra_loader) -> "Iterator[FlatProgramAPI]":
    # TODO: add transaction in order to restore state by tests
    yield ghidra_loader
