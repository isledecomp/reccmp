import hashlib
from pathlib import Path
from typing import Callable, Iterator, TYPE_CHECKING
import pytest
from _pytest.config.argparsing import Parser

from reccmp.formats import NEImage, PEImage, detect_image
from tests.binfiles_test_setup import LEGO1_SHA256, SKI_SHA256

from .ghidra_integration_test_setup import ghidra_integration_test_program

# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Program


REQUIRE_BINFILES_OPTION = "--require-binfiles"
REQUIRE_GHIDRA_OPTION = "--require-ghidra"


def pytest_addoption(parser: Parser):
    """Allow the option to run tests against sample binaries."""
    parser.addoption("--binfiles", action="store", help="Path to sample binary files.")
    parser.addoption(
        REQUIRE_BINFILES_OPTION,
        action="store_true",
        help="Fail tests that depend on binary samples if we cannot load them.",
    )
    parser.addoption(
        "--require-ghidra",
        action="store_true",
        help=f"Fail tests that depend on Ghidra it is not available. Implies {REQUIRE_BINFILES_OPTION}.",
    )


def check_hash(path: Path, hash_str: str) -> bool:
    with path.open("rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
        return digest == hash_str


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
        if pytestconfig.getoption(REQUIRE_BINFILES_OPTION) or pytestconfig.getoption(
            REQUIRE_GHIDRA_OPTION
        ):
            pytest.fail(pytrace=False, reason=not_found_reason)

        pytest.skip(allow_module_level=True, reason=not_found_reason)
        # Unreachable because both skip and fail raise exceptions, but `pylint` complains otherwise
        return None

    yield loader


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


@pytest.fixture(name="ghidra_program", scope="session")
def fixture_ghidra_loader(
    pytestconfig, request: pytest.FixtureRequest, bin_loader: Callable[[str, str], Path]
) -> "Iterator[FlatProgramAPI]":
    try:
        yield from ghidra_integration_test_program(request, bin_loader)
    # pylint: disable-next=broad-exception-caught # We cannot control all the exceptions that can be raised here
    except Exception as e:
        reason = f"Unable to start Ghidra: {e}"

        if pytestconfig.getoption(REQUIRE_GHIDRA_OPTION):
            pytest.fail(pytrace=False, reason=reason)

        pytest.skip(allow_module_level=True, reason=reason)


@pytest.fixture(name="ghidra", scope="function")
def fixture_ghidra_program(ghidra_program: "Program") -> "Iterator[FlatProgramAPI]":
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
