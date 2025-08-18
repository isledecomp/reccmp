import dataclasses
from pathlib import Path
import pytest
from reccmp.isledecomp.formats.image import Image
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)


@dataclasses.dataclass
class RawImage(Image):
    """For testing functions implemented in the base Image class."""

    # Total size of the image.
    # If it is more than the size of physical data, the remainder is uninitialized (all null).
    size: int

    @classmethod
    def from_memory(cls, data: bytes, size: int = 0) -> "RawImage":
        if size is None:
            maxsize = len(data)
        else:
            maxsize = max(size, len(data))

        view = memoryview(data).toreadonly()

        image = cls(data=data, view=view, filepath=Path(""), size=maxsize)
        return image

    def seek(self, vaddr: int) -> tuple[bytes, int]:
        if 0 <= vaddr < self.size:
            return (self.data[vaddr:], self.size - vaddr)

        raise InvalidVirtualAddressError


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


def test_raw_all_initialized():
    img = RawImage.from_memory(b"test\x00")
    # Should seek to correct spot.
    assert img.seek(0) == (b"test\x00", 5)
    assert img.seek(2) == (b"st\x00", 3)

    # Should read only the specified number of bytes.
    assert img.read(0, 0) == b""
    assert img.read(0, 4) == b"test"
    assert img.read(2, 2) == b"st"

    # Should detect null-terminator and end the string.
    assert img.read_string(0) == b"test"
    assert img.read_string(4) == b""

    # Cannot read -1 bytes.
    with pytest.raises(InvalidVirtualReadError):
        img.read(0, -1)

    # Cannot read more bytes than are in the image.
    with pytest.raises(InvalidVirtualReadError):
        img.read(0, 10)

    # Fail for any addresses outside the bounds of the image.
    with pytest.raises(InvalidVirtualAddressError):
        img.seek(-1)

    with pytest.raises(InvalidVirtualAddressError):
        img.seek(6)

    with pytest.raises(InvalidVirtualAddressError):
        img.read(-1, 1)

    with pytest.raises(InvalidVirtualAddressError):
        img.read(6, 1)

    with pytest.raises(InvalidVirtualAddressError):
        img.read_string(-1)

    with pytest.raises(InvalidVirtualAddressError):
        img.read_string(6)


def test_raw_partially_initialized():
    img = RawImage.from_memory(b"test", size=10)
    # Seek should show only the physical bytes that exist.
    # The number of bytes remaining should take the full image size into account.
    assert img.seek(0) == (b"test", 10)
    assert img.seek(2) == (b"st", 8)
    assert img.seek(4) == (b"", 6)
    assert img.seek(9) == (b"", 1)

    # Reads should include uninitialized bytes.
    assert img.read(0, 10) == b"test\x00\x00\x00\x00\x00\x00"
    assert img.read(0, 4) == b"test"
    assert img.read(2, 2) == b"st"
    assert img.read(6, 4) == b"\x00\x00\x00\x00"

    # Should detect null-terminator even though it is part of uninitialized data.
    assert img.read_string(0) == b"test"
    assert img.read_string(5) == b""
    assert img.read_string(9) == b""


def test_raw_all_uninitialized():
    img = RawImage.from_memory(b"", size=10)
    # There are no physical bytes but make sure the remaining count is correct.
    assert img.seek(0) == (b"", 10)
    assert img.seek(9) == (b"", 1)

    # Reads should include uninitialized bytes.
    assert img.read(0, 1) == b"\x00"
    assert img.read(0, 10) == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    # Reading from any valid address results in the empty string.
    assert img.read_string(0) == b""
    assert img.read_string(6) == b""


def test_widechar():
    img = RawImage.from_memory(b"t\x00e\x00s\x00t\x00\x00\x00")
    data = img.read_widechar(0)
    assert data.decode("utf-16-le") == "test"
