import re
import dataclasses
from typing import Iterator
from pathlib import Path
from .exceptions import InvalidVirtualReadError, InvalidStringError

# Matches 0-to-N non-null bytes.
r_szstring = re.compile(rb"[^\x00]*")

# Matches pairs of bytes until both are null.
r_widestring = re.compile(rb"(?:(?:[^\x00]\x00)|(?:\x00[^\x00])|(?:[^\x00][^\x00]))*")


@dataclasses.dataclass(frozen=True)
class ImageRegion:
    addr: int
    data: bytes
    size: int = 0

    def __post_init__(self):
        """The optional size parameter allows you to set virtual size for the region
        if this is larger than the number of physical bytes."""
        object.__setattr__(self, "size", max(len(self.data), self.size))

    @property
    def range(self) -> range:
        return range(self.addr, self.addr + self.size)


@dataclasses.dataclass
class Image:
    filepath: Path
    view: memoryview = dataclasses.field(repr=False)
    data: bytes = dataclasses.field(repr=False)

    def seek(self, vaddr: int) -> tuple[bytes, int]:
        """Must be implemented for each image.
        1. Go to the position in virtual memory for the given address.
        2. If it is valid, return a tuple with:
            a. bytes or memoryview with the relevant stream of data that begins at the address.
            b. number of valid bytes remaining (including the size of whatever is in 'a').
        3. If the address is not valid, raise InvalidVirtualAddressError"""
        raise NotImplementedError

    def get_code_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError

    def get_data_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError

    def get_const_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError

    def read_string(self, vaddr: int) -> bytes:
        (view, _) = self.seek(vaddr)

        match = r_szstring.match(view)
        if match is None:
            raise InvalidStringError(f"Cannot read string at {vaddr:x}")

        return match.group(0)

    def read_widechar(self, vaddr: int) -> bytes:
        (view, _) = self.seek(vaddr)

        match = r_widestring.match(view)

        # We expect to support only images that use UTF-16 LE for the near-to-medium term.
        # However: we only verify that we return a string that *could* be decoded.
        # The caller should trap UnicodeDecodeError.
        if match is None or len(match.group(0)) % 2 != 0:
            raise InvalidStringError(f"Cannot read widechar string at {vaddr:x}")

        return match.group(0)

    def read(self, vaddr: int, size: int) -> bytes:
        (view, remaining) = self.seek(vaddr)
        if size < 0 or size > remaining:
            raise InvalidVirtualReadError(
                f"{self.filepath} : Cannot read {size} bytes from 0x{vaddr:x}"
            )

        if size < len(view):
            return bytes(view[:size])

        # If we need to read uninitialized bytes, copy the physical bytes we have onto the buffer.
        data = bytearray(size)
        data[: len(view)] = view
        return data
