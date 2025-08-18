import re
import dataclasses
from pathlib import Path
from .exceptions import InvalidVirtualReadError

# Matches 0-to-N non-null bytes.
r_szstring = re.compile(rb"[^\x00]*")

# Matches pairs of bytes until both are null.
r_widestring = re.compile(rb"(?:(?:[^\x00]\x00)|(?:\x00[^\x00])|(?:[^\x00][^\x00]))*")


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

    def read_string(self, vaddr: int) -> bytes:
        (view, _) = self.seek(vaddr)

        match = r_szstring.match(view)
        if match:
            return match.group(0)

        return b""

    def read_widechar(self, vaddr: int) -> bytes:
        (view, _) = self.seek(vaddr)

        match = r_widestring.match(view)
        # Since we are dealing with only UTF-16 LE at the outset,
        # just make sure we don't deliver a string with an odd number of bytes
        # that will definitely fail to decode.
        # Later on we may want to have each image type do things differently
        # based on the expectations of the platform.
        if match and len(match.group(0)) % 2 == 0:
            return match.group(0)

        return b""

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
