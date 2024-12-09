from dataclasses import dataclass
from pathlib import Path
import struct

from .image import Image


class MZHeaderNotFoundError(ValueError):
    """MZ magic string not found"""


# pylint: disable=too-many-instance-attributes
@dataclass(frozen=True)
class ImageDosHeader:
    # Order is significant!
    e_magic: bytes
    e_cblp: int
    e_cp: int
    e_crlc: int
    e_cparhdr: int
    e_minalloc: int
    e_maxalloc: int
    e_ss: int
    e_sp: int
    e_csum: int
    e_ip: int
    e_cs: int
    e_lfarlc: int
    e_ovno: int
    e_res: tuple[int, int, int, int]
    e_oemid: int
    e_oeminfo: int
    e_res2: tuple[int, int, int, int, int, int, int, int, int, int]
    e_lfanew: int

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["ImageDosHeader", int]:
        if not cls.taste(data, offset):
            raise ValueError
        struct_fmt = "<2s29HI"
        struct_size = struct.calcsize(struct_fmt)
        items = struct.unpack_from(struct_fmt, data, offset)
        result = cls(
            *items[:14],
            items[14:18],
            *items[18:20],
            items[20:30],
            items[30],
        )
        return result, offset + struct_size

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        (magic,) = struct.unpack_from("<2s", data, offset)
        return magic == b"MZ"


@dataclass
class MZImage(Image):
    mz_header: ImageDosHeader

    @classmethod
    def from_memory(
        cls, data: bytes, mz_header: ImageDosHeader, filepath: Path
    ) -> "Image":
        return cls(
            filepath=filepath, data=data, view=memoryview(data), mz_header=mz_header
        )

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        return ImageDosHeader.taste(data, offset=offset)
