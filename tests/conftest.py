import hashlib
from pathlib import Path
from typing import Callable, Iterator, TYPE_CHECKING
import pytest
from _pytest.config.argparsing import Parser

from reccmp.formats import NEImage, PEImage, detect_image

from .binfiles_test_setup import BINFILE_LEGO1, BINFILE_SKI, TestBinfile
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
        REQUIRE_GHIDRA_OPTION,
        action="store_true",
        help="Fail tests that depend on Ghidra it is not available.",
    )


def check_hash(path: Path, hash_str: str) -> bool:
    with path.open("rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
        return digest == hash_str


@pytest.fixture(name="bin_loader", scope="session")
def fixture_loader(pytestconfig) -> Iterator[Callable[[TestBinfile, bool], Path]]:
    # Search path is ./tests/binfiles unless the user provided an alternate location.
    binfiles_arg = pytestconfig.getoption("--binfiles")
    if binfiles_arg is not None:
        binfile_path = Path(binfiles_arg).resolve()
    else:
        binfile_path = Path(__file__).resolve().parent / "binfiles"

    def loader(binfile: TestBinfile, file_is_required: bool) -> Path:
        file = binfile_path / binfile.filename
        if file.exists():
            if not check_hash(file, binfile.hash_str):
                pytest.fail(
                    pytrace=False,
                    reason="Did not match expected " + binfile.filename.upper(),
                )

            return file

        not_found_reason = "No path to " + binfile.filename.upper()
        if file_is_required or pytestconfig.getoption(REQUIRE_BINFILES_OPTION):
            pytest.fail(pytrace=False, reason=not_found_reason)

        pytest.skip(allow_module_level=True, reason=not_found_reason)
        # Unreachable because pytest.skip raises unconditionally, but `pylint` complains without this return statement
        return None

    yield loader


@pytest.fixture(name="binfile", scope="session")
def fixture_binfile(
    bin_loader: Callable[[TestBinfile, bool], Path],
) -> Iterator[PEImage]:
    image = detect_image(bin_loader(BINFILE_LEGO1, False))
    assert isinstance(image, PEImage)
    yield image


@pytest.fixture(name="skifree", scope="session")
def fixture_skifree(
    bin_loader: Callable[[TestBinfile, bool], Path],
) -> Iterator[NEImage]:
    image = detect_image(bin_loader(BINFILE_SKI, False))
    assert isinstance(image, NEImage)
    yield image


@pytest.fixture(name="ghidra_program", scope="session")
def fixture_ghidra_loader(
    pytestconfig,
    request: pytest.FixtureRequest,
    bin_loader: Callable[[TestBinfile, bool], Path],
) -> "Iterator[FlatProgramAPI]":
    ghidra_is_required = pytestconfig.getoption(REQUIRE_GHIDRA_OPTION)

    try:
        yield from ghidra_integration_test_program(
            request, lambda binfile: bin_loader(binfile, ghidra_is_required)
        )
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
