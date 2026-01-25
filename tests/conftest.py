import hashlib
from pathlib import Path
from typing import Callable, Iterator
import pytest

from reccmp.formats import Image, NEImage, PEImage, detect_image


def pytest_addoption(parser):
    """Allow the option to run tests against sample binaries."""
    parser.addoption("--binfiles", action="store", help="Path to sample binary files.")
    parser.addoption(
        "--require-binfiles",
        action="store_true",
        help="Fail tests that depend on binary samples if we cannot load them.",
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
