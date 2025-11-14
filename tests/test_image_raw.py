import dataclasses
from pathlib import Path
import pytest
from reccmp.isledecomp.formats.image import Image
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)


# pylint: disable=abstract-method
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

    with pytest.raises(InvalidVirtualAddressError):
        img.read_widechar(-1)

    with pytest.raises(InvalidVirtualAddressError):
        img.read_widechar(6)


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


def test_widechar_null_terminator_included():
    """Reading pairs of bytes until both are null. No expectation on encoding."""
    img = RawImage.from_memory(b"\x00\x00")
    assert img.read_widechar(0) == b""

    # UTF-16 LE
    img = RawImage.from_memory(b"t\x00e\x00s\x00t\x00\x00\x00")
    data = img.read_widechar(0)
    assert data.decode("utf-16-le") == "test"

    # UTF-16 BE
    img = RawImage.from_memory(b"\x00t\x00e\x00s\x00t\x00\x00")
    data = img.read_widechar(0)
    assert data.decode("utf-16-be") == "test"

    # Not restricted to cases where every other byte is null
    img = RawImage.from_memory(b"test\x00\x00")
    data = img.read_widechar(0)
    assert data == b"test"


def test_widechar_null_terminator_missing():
    """I don't think it's likely this will happen, but this is to test the case
    where the string appears at the very end of physical memory."""
    img = RawImage.from_memory(b"\x00")
    assert img.read_widechar(0) == b""

    with pytest.raises(InvalidVirtualAddressError):
        img = RawImage.from_memory(b"")
        img.read_widechar(0)

    # Throws InvalidVirtualAddressError if not for the uninitialized padding.
    img = RawImage.from_memory(b"", size=1)
    assert img.read_widechar(0) == b""

    # UTF-16 LE: 1 byte for null-terminator
    img = RawImage.from_memory(b"t\x00e\x00s\x00t\x00\x00")
    data = img.read_widechar(0)
    assert data.decode("utf-16-le") == "test"

    # UTF-16 LE: no null-terminator
    img = RawImage.from_memory(b"t\x00e\x00s\x00t\x00")
    data = img.read_widechar(0)
    assert data.decode("utf-16-le") == "test"

    # UTF-16 BE: 1 byte for null-terminator
    img = RawImage.from_memory(b"\x00t\x00e\x00s\x00t\x00")
    data = img.read_widechar(0)
    assert data.decode("utf-16-be") == "test"

    # UTF-16 BE: no null-terminator
    img = RawImage.from_memory(b"\x00t\x00e\x00s\x00t")
    data = img.read_widechar(0)
    assert data.decode("utf-16-be") == "test"

    # Not restricted to cases where every other byte is null
    img = RawImage.from_memory(b"test")
    data = img.read_widechar(0)
    assert data == b"test"


STRING_READ_SAMPLES = (
    # No string for any sequence of null bytes.
    (b"\x00", b"", b""),
    (b"\x00\x00", b"", b""),
    (b"\x00\x00\x00", b"", b""),
    (b"\x00\x00\x00\x00", b"", b""),
    # Don't return a widechar until we have two physical bytes to read.
    # If the second byte of the final wide character of the string is 0
    # then it must be in physical memory. This is hopefully always the case.
    (b"A", b"A", b""),
    (b"A\x00", b"A", b"A\x00"),
    (b"A\x00B", b"A", b"A\x00"),
    (b"A\x00B\x00", b"A", b"A\x00B\x00"),
    # Widechar allows for the first byte to be null unless the second one is too.
    (b"\x00ABC", b"", b"\x00ABC"),
    (b"\x00\x00ABCD", b"", b""),
    # Widechar should ignore the last byte even though none of the bytes are null.
    (b"ABC", b"ABC", b"AB"),
)


@pytest.mark.parametrize(
    "memory, expected_string, expected_widechar", STRING_READ_SAMPLES
)
def test_string_reads(memory: bytes, expected_string: bytes, expected_widechar: bytes):
    """An attempt to cover all situations where our string regex would fail to match.
    We don't expect to see an InvalidStringError."""
    img = RawImage.from_memory(memory)
    assert img.read_string(0) == expected_string
    assert img.read_widechar(0) == expected_widechar
