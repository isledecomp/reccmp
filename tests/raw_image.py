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

    base_addr: int
    """The starting virtual address in the image. (Equivalent to PE imagebase)"""

    @classmethod
    def from_memory(
        cls, data: bytes = b"", *, base_addr: int = 0, bss: int = 0
    ) -> "RawImage":
        """Creates the image's memory in this order:
        1. Physical bytes from the `data` parameter.
        2. Zero or more bytes of uninitialized data as directed by the `bss` parameter.

        Setting the optional `base_addr` parameter allows for address values that more
        closely imitate a real image where this is needed.
        """
        assert bss >= 0
        assert base_addr >= 0
        size = len(data) + bss
        view = memoryview(data).toreadonly()

        return cls(
            data=data, view=view, filepath=Path(""), size=size, base_addr=base_addr
        )

    def seek(self, vaddr: int) -> tuple[memoryview, int]:
        offset = vaddr - self.base_addr
        if 0 <= offset < self.size:
            return (memoryview(self.data[offset:]), self.size - offset)

        raise InvalidVirtualAddressError
