"""Mock Image to be used wherever tests need an image with specific data or BSS region.
This might find a use later as a general-purpose image type (e.g. .COM files with no header)
but until then it will live under the tests/ directory."""

import dataclasses
from pathlib import Path
from reccmp.formats import Image
from reccmp.formats.exceptions import InvalidVirtualAddressError


# pylint: disable=abstract-method
@dataclasses.dataclass
class RawImage(Image):
    """For testing functions implemented in the base Image class."""

    # Total size of the image.
    # If it is more than the size of physical data, the remainder is uninitialized (all null).
    size: int

    @classmethod
    def from_memory(cls, data: bytes = b"", *, bss: int = 0) -> "RawImage":
        assert bss >= 0
        size = len(data) + bss
        view = memoryview(data).toreadonly()

        image = cls(data=data, view=view, filepath=Path(""), size=size)
        return image

    def seek(self, vaddr: int) -> tuple[bytes, int]:
        if 0 <= vaddr < self.size:
            return (self.data[vaddr:], self.size - vaddr)

        raise InvalidVirtualAddressError
