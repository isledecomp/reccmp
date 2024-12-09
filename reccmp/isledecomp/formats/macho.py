import struct
from dataclasses import dataclass
from pathlib import Path

from .image import Image


# pylint: disable=too-many-instance-attributes
@dataclass(frozen=True)
class MachOHeader:
    magic: int
    cpu_type: int
    cpu_subtype: int
    file_type: int
    number_of_load_commands: int
    size_of_load_commands: int
    flags: int
    reserved: int

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["MachOHeader", int]:
        struct_fmt = "<8I"
        items = struct.unpack_from(struct_fmt, data, offset)
        return cls(*items), offset + struct.calcsize(struct_fmt)


@dataclass
class MachOImage(Image):
    header: MachOHeader

    @classmethod
    def from_memory(cls, data: bytes, offset: int, filepath: Path) -> "MachOImage":
        if not cls.taste(data, offset):
            raise ValueError
        header, _ = MachOHeader.from_memory(data, offset)
        return cls(filepath=filepath, data=data, view=memoryview(data), header=header)

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        (magic_le,) = struct.unpack_from("<I", data, offset)
        (magic_be,) = struct.unpack_from(">I", data, offset)
        return magic_le in (
            0xFEEDFACE,
            0xFEEDFACF,
        ) or magic_be in (
            0xFEEDFACE,
            0xFEEDFACF,
            0xCAFEBABE,
        )
