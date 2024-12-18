import hashlib
from pathlib import Path
from typing import Iterator
import pytest

from reccmp.isledecomp import PEImage, detect_image


def pytest_addoption(parser):
    """Allow the option to run tests against the original LEGO1.DLL."""
    parser.addoption("--lego1", action="store", help="Path to LEGO1.DLL")


# LEGO1.DLL: v1.1 English, September
LEGO1_SHA256 = "14645225bbe81212e9bc1919cd8a692b81b8622abb6561280d99b0fc4151ce17"


@pytest.fixture(name="binfile", scope="session")
def fixture_binfile(pytestconfig) -> Iterator[PEImage]:
    filename = pytestconfig.getoption("--lego1")

    # Skip this if we have not provided the path to LEGO1.dll.
    if filename is None:
        pytest.skip(allow_module_level=True, reason="No path to LEGO1")

    filename = Path(filename)
    with filename.open("rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
        if digest != LEGO1_SHA256:
            pytest.fail(reason="Did not match expected LEGO1.DLL")

    image = detect_image(filename)
    assert isinstance(image, PEImage)
    yield image
