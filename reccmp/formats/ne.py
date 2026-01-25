"""
Based on the following resources:
- https://github.com/bitwiseworks/os2tk45/blob/master/h/newexe.h
- https://github.com/qb40/exe-format/blob/master/README.txt
"""

import dataclasses
import struct
from pathlib import Path
from enum import IntEnum, IntFlag

from .image import Image
from .mz import ImageDosHeader


class NESegmentFlags(IntFlag):
    # pylint: disable=implicit-flag-alias
    NESOLO = 0x0001  # Solo data
    NEINST = 0x0002  # Instance data
    NEPPLI = 0x0004  # Per-Process Library Initialization
    NEPROT = 0x0008  # Runs in protected mode only
    NEI086 = 0x0010  # 8086 instructions
    NEI286 = 0x0020  # 286 instructions
    NEI386 = 0x0040  # 386 instructions
    NEFLTP = 0x0080  # Floating-point instructions
    NENOTWINCOMPAT = 0x0100  # Not compatible with P.M. Windowing
    NEWINCOMPAT = 0x0200  # Compatible with P.M. Windowing
    NEWINAPI = 0x0300  # Uses P.M. Windowing API
    NEAPPTYP = 0x0700  # Application type mask
    NEBOUND = 0x0800  # Bound Family/API
    NEIERR = 0x2000  # Errors in image
    NEPRIVLIB = 0x4000  # A one customer Windows 3.0 library
    NENOTP = 0x8000  # Not a process


class NETargetOSFlags(IntEnum):
    NE_UNKNOWN = 0  # Unknown (any "new-format" OS)
    NE_OS2 = 1  # OS/2 (default)
    NE_WINDOWS = 2  # Windows
    NE_DOS = 3  # DOS 4.x
    NE_DEV386 = 4  # Windows 386


@dataclasses.dataclass(frozen=True)
class NESegmentTableEntry:
    ns_sector: int  # File sector of start of segment
    ns_cbseg: int  # Number of bytes in file
    ns_flags: int  # Attribute flags
    ns_minalloc: int  # Minimum allocation in bytes

    @classmethod
    def from_memory(
        cls, data: bytes, offset: int, count: int
    ) -> tuple[tuple["NESegmentTableEntry", ...], int]:
        struct_fmt = "<4H"
        struct_size = struct.calcsize(struct_fmt)
        items = tuple(
            cls(*items)
            for items in struct.iter_unpack(
                struct_fmt, data[offset : offset + count * struct_size]
            )
        )
        return items, offset + count * struct_size


@dataclasses.dataclass(frozen=True)
class NewExeHeader:
    # pylint: disable=too-many-instance-attributes
    ne_magic: bytes  # Magic number NE_MAGIC
    ne_ver: int  # Version number
    ne_rev: int  # Revision number
    ne_enttab: int  # Offset of Entry Table
    ne_cbenttab: int  # Number of bytes in Entry Table
    ne_crc: int  # Checksum of whole file
    ne_flags: NESegmentFlags  # Flag word
    ne_autodata: int  # Automatic data segment number
    ne_heap: int  # Initial heap allocation
    ne_stack: int  # Initial stack allocation
    ne_csip: tuple[int, int]  # Initial CS:IP setting
    ne_sssp: tuple[int, int]  # Initial SS:SP setting
    ne_cseg: int  # Count of file segments
    ne_cmod: int  # Entries in Module Reference Table
    ne_cbnrestab: int  # Size of non-resident name table
    ne_segtab: int  # Offset of Segment Table (Relative to NE header)
    ne_rsrctab: int  # Offset of Resource Table (Relative to NE header)
    ne_restab: int  # Offset of resident name Table (Relative to NE header)
    ne_modtab: int  # Offset of Module Reference Table (Relative to NE header)
    ne_imptab: int  # Offset of Imported Names Table (Relative to NE header)
    ne_nrestab: int  # Offset of Non-resident Names Table (File offset)
    ne_cmovent: int  # Count of movable entries
    ne_align: int  # Segment alignment shift count
    ne_cres: int  # Count of resource entries
    ne_exetyp: NETargetOSFlags  # Target operating system
    ne_flagsothers: int  # Other .EXE flags
    ne_pretthunks: int  # Windows 3.0 - offset to return thunks
    ne_psegrefbytes: int  # Windows 3.0 - offset to segment ref. bytes
    ne_swaparea: int  # Windows 3.0 - minimum code swap size
    ne_expver: int  # Windows 3.0 - expected windows version number

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["NewExeHeader", int]:
        if not cls.taste(data, offset):
            raise ValueError
        struct_fmt = "<2s2B2HI16HI3H2B4H"
        struct_size = struct.calcsize(struct_fmt)
        # fmt: off
        items: tuple[bytes, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int] = (
            struct.unpack_from(struct_fmt, data, offset)
        )
        # fmt: on
        result = cls(
            *items[:6],
            NESegmentFlags(items[6]),
            *items[7:10],
            (items[11], items[10]),  # CS:IP
            (items[13], items[12]),  # SS:SP
            *items[14:26],
            NETargetOSFlags(items[26]),
            *items[27:],
        )
        return result, offset + struct_size

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        (magic,) = struct.unpack_from("<2s", data, offset)
        return magic == b"NE"


@dataclasses.dataclass
class NEImage(Image):
    mz_header: ImageDosHeader
    header: NewExeHeader
    segments: tuple[NESegmentTableEntry, ...]

    @classmethod
    def from_memory(
        cls, data: bytes, mz_header: ImageDosHeader, filepath: Path
    ) -> "NEImage":
        offset = mz_header.e_lfanew
        view = memoryview(data)
        header, _ = NewExeHeader.from_memory(data, offset=offset)
        segments, _ = NESegmentTableEntry.from_memory(
            data, offset=offset + header.ne_segtab, count=header.ne_cseg
        )

        return cls(
            filepath=filepath,
            data=data,
            view=view,
            mz_header=mz_header,
            header=header,
            segments=segments,
        )

    def seek(self, vaddr: int) -> tuple[bytes, int]:
        raise NotImplementedError
