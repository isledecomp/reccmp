import hashlib
from typing import Iterator
import pytest

from reccmp.isledecomp.bin import (
    Bin as IsleBin,
)


def pytest_addoption(parser):
    """Allow the option to run tests against the original LEGO1.DLL."""
    parser.addoption("--lego1", action="store", help="Path to LEGO1.DLL")


# LEGO1.DLL: v1.1 English, September
LEGO1_SHA256 = "14645225bbe81212e9bc1919cd8a692b81b8622abb6561280d99b0fc4151ce17"


@pytest.fixture(name="binfile", scope="session")
def fixture_binfile(pytestconfig) -> Iterator[IsleBin]:
    filename = pytestconfig.getoption("--lego1")

    # Skip this if we have not provided the path to LEGO1.dll.
    if filename is None:
        pytest.skip(allow_module_level=True, reason="No path to LEGO1")

    with open(filename, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
        if digest != LEGO1_SHA256:
            pytest.fail(reason="Did not match expected LEGO1.DLL")

    with IsleBin(filename, find_str=True) as islebin:
        yield islebin
