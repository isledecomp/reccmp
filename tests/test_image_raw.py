import pytest
from reccmp.isledecomp.formats.raw import RawImage
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)


def test_raw_size_parameter():
    """The size parameter determines the total size of the image.
    It cannot be less than the size of the initialized data."""
    # Automatically set using len(data)
    img = RawImage.from_memory(b"test")
    assert img.size == 4

    # Use the max of len(data) and size parameter.
    img = RawImage.from_memory(b"test", size=0)
    assert img.size == 4

    img = RawImage.from_memory(b"test", size=10)
    assert img.size == 10

    # Size cannot be less than len(data) even if that is zero.
    img = RawImage.from_memory(b"", size=-10)
    assert img.size == 0

    img = RawImage.from_memory(b"", size=10)
    assert img.size == 10


def test_read_all_initialized():
    img = RawImage.from_memory(b"test\x00")
    assert img.read(0, 0) == b""
    assert img.read(0, 4) == b"test"
    assert img.read(2, 2) == b"st"

    assert img.read_string(0) == b"test"
    assert img.read_string(4) == b""

    with pytest.raises(InvalidVirtualReadError):
        img.read(0, -1)

    with pytest.raises(InvalidVirtualReadError):
        img.read(0, 10)

    with pytest.raises(InvalidVirtualAddressError):
        img.read(-1, 1)

    with pytest.raises(InvalidVirtualAddressError):
        img.read(6, 1)

    with pytest.raises(InvalidVirtualAddressError):
        img.read_string(-1)

    with pytest.raises(InvalidVirtualAddressError):
        img.read_string(6)


def test_read_partially_initialized():
    img = RawImage.from_memory(b"test", size=10)
    assert img.read(0, 10) == b"test\x00\x00\x00\x00\x00\x00"
    assert img.read(0, 4) == b"test"
    assert img.read(2, 2) == b"st"
    assert img.read(6, 4) == b"\x00\x00\x00\x00"

    assert img.read_string(0) == b"test"
    assert img.read_string(5) == b""
    assert img.read_string(9) == b""


def test_read_all_uninitialized():
    img = RawImage.from_memory(b"", size=10)
    assert img.read(0, 0) == b""
    assert img.read(0, 10) == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    assert img.read_string(0) == b""
