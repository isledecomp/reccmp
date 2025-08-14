"""For testing functions implemented in the base Image class."""

import dataclasses
from pathlib import Path
from .image import Image
from .exceptions import InvalidVirtualAddressError


@dataclasses.dataclass
class RawImage(Image):
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
