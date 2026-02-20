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
    """Image subclass with contents declared at runtime.
    Creates a single section with either physical or uninitialized data, or both in sequence.
    """

    size: int
    """Total size of the image including physical bytes (`data` property) and uninitialized memory."""

    @classmethod
    def from_memory(cls, data: bytes = b"", *, bss: int = 0) -> "RawImage":
        """Creates the image's memory in this order:
        1. Physical bytes from the `data` parameter.
        2. Zero or more bytes of uninitialized data as directed by the `bss` parameter.
        """
        assert bss >= 0
        size = len(data) + bss
        view = memoryview(data).toreadonly()

        return cls(data=data, view=view, filepath=Path(""), size=size)

    def seek(self, vaddr: int) -> tuple[bytes, int]:
        if 0 <= vaddr < self.size:
            return (self.data[vaddr:], self.size - vaddr)

        raise InvalidVirtualAddressError
