"""Type enum modified from cvinfo.h released under MIT license.
https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h
See `LICENSE.cvdump.txt` for details.
"""

from enum import Enum
from types import MappingProxyType
from typing import NamedTuple


class CvdumpTypeKey(int):
    def is_scalar(self) -> bool:
        return self < 0x1000

    @classmethod
    def from_str(cls, key: str) -> "CvdumpTypeKey":
        if key[0] == "0":
            return cls(int(key, 16))

        # Should cover both "T_" and "???" cases.
        return cls(int(key[-5:-1], 16))


class CvInfoType(NamedTuple):
    key: CvdumpTypeKey
    """The integer type key."""
    name: str
    """The name of this type as given in cvinfo.h."""
    fmt: str
    """The struct.unpack format char(s) for this type."""
    size: int
    """The type's footprint in bytes."""
    pointer: CvdumpTypeKey | None
    """If set, this type is a pointer to another CVinfo type."""
    verified: bool
    """Is this a type we have seen in the field?"""


# fmt: off
_CVINFO_TYPES = (

#      Special Types

    CvInfoType(key=CvdumpTypeKey(0x0000),  name="T_NOTYPE",       fmt="",     size=0,   pointer=None,                   verified=True ), # uncharacterized type (no type)
    CvInfoType(key=CvdumpTypeKey(0x0001),  name="T_ABS",          fmt="",     size=0,   pointer=None,                   verified=False), # absolute symbol
    CvInfoType(key=CvdumpTypeKey(0x0002),  name="T_SEGMENT",      fmt="",     size=0,   pointer=None,                   verified=False), # segment type
    CvInfoType(key=CvdumpTypeKey(0x0003),  name="T_VOID",         fmt="",     size=0,   pointer=None,                   verified=True ), # void
    CvInfoType(key=CvdumpTypeKey(0x0008),  name="T_HRESULT",      fmt="I",    size=4,   pointer=None,                   verified=True ), # OLE/COM HRESULT
    CvInfoType(key=CvdumpTypeKey(0x0408),  name="T_32PHRESULT",   fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0008),  verified=True ), # OLE/COM HRESULT __ptr32 *
    CvInfoType(key=CvdumpTypeKey(0x0608),  name="T_64PHRESULT",   fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0008),  verified=False), # OLE/COM HRESULT __ptr64 *

    CvInfoType(key=CvdumpTypeKey(0x0103),  name="T_PVOID",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0003),  verified=False), # near pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0203),  name="T_PFVOID",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0003),  verified=False), # far pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0303),  name="T_PHVOID",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0003),  verified=False), # huge pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0403),  name="T_32PVOID",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0003),  verified=True ), # 32 bit pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0503),  name="T_32PFVOID",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0003),  verified=False), # 16:32 pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0603),  name="T_64PVOID",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0003),  verified=False), # 64 bit pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0004),  name="T_CURRENCY",     fmt="",     size=0,   pointer=None,                   verified=False), # BASIC 8 byte currency value
    CvInfoType(key=CvdumpTypeKey(0x0005),  name="T_NBASICSTR",    fmt="",     size=0,   pointer=None,                   verified=False), # Near BASIC string
    CvInfoType(key=CvdumpTypeKey(0x0006),  name="T_FBASICSTR",    fmt="",     size=0,   pointer=None,                   verified=False), # Far BASIC string
    CvInfoType(key=CvdumpTypeKey(0x0007),  name="T_NOTTRANS",     fmt="",     size=0,   pointer=None,                   verified=False), # type not translated by cvpack
    CvInfoType(key=CvdumpTypeKey(0x0060),  name="T_BIT",          fmt="",     size=0,   pointer=None,                   verified=False), # bit
    CvInfoType(key=CvdumpTypeKey(0x0061),  name="T_PASCHAR",      fmt="",     size=0,   pointer=None,                   verified=False), # Pascal CHAR
    CvInfoType(key=CvdumpTypeKey(0x0062),  name="T_BOOL32FF",     fmt="i",    size=4,   pointer=None,                   verified=False), # 32-bit BOOL where true is 0xffffffff


#      Character types

    CvInfoType(key=CvdumpTypeKey(0x0010),  name="T_CHAR",         fmt="b",    size=1,   pointer=None,                   verified=True ), # 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0110),  name="T_PCHAR",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0010),  verified=False), # 16 bit pointer to 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0210),  name="T_PFCHAR",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0010),  verified=False), # 16:16 far pointer to 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0310),  name="T_PHCHAR",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0010),  verified=False), # 16:16 huge pointer to 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0410),  name="T_32PCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0010),  verified=True ), # 32 bit pointer to 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0510),  name="T_32PFCHAR",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0010),  verified=False), # 16:32 pointer to 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0610),  name="T_64PCHAR",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0010),  verified=False), # 64 bit pointer to 8 bit signed

    CvInfoType(key=CvdumpTypeKey(0x0020),  name="T_UCHAR",        fmt="B",    size=1,   pointer=None,                   verified=True ), # 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0120),  name="T_PUCHAR",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0020),  verified=False), # 16 bit pointer to 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0220),  name="T_PFUCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0020),  verified=False), # 16:16 far pointer to 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0320),  name="T_PHUCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0020),  verified=False), # 16:16 huge pointer to 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0420),  name="T_32PUCHAR",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0020),  verified=True ), # 32 bit pointer to 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0520),  name="T_32PFUCHAR",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0020),  verified=False), # 16:32 pointer to 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0620),  name="T_64PUCHAR",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0020),  verified=False), # 64 bit pointer to 8 bit unsigned


#      really a character types

    CvInfoType(key=CvdumpTypeKey(0x0070),  name="T_RCHAR",        fmt="c",    size=1,   pointer=None,                   verified=True ), # really a char
    CvInfoType(key=CvdumpTypeKey(0x0170),  name="T_PRCHAR",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0070),  verified=False), # 16 bit pointer to a real char
    CvInfoType(key=CvdumpTypeKey(0x0270),  name="T_PFRCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0070),  verified=False), # 16:16 far pointer to a real char
    CvInfoType(key=CvdumpTypeKey(0x0370),  name="T_PHRCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0070),  verified=False), # 16:16 huge pointer to a real char
    CvInfoType(key=CvdumpTypeKey(0x0470),  name="T_32PRCHAR",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0070),  verified=True ), # 32 bit pointer to a real char
    CvInfoType(key=CvdumpTypeKey(0x0570),  name="T_32PFRCHAR",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0070),  verified=False), # 16:32 pointer to a real char
    CvInfoType(key=CvdumpTypeKey(0x0670),  name="T_64PRCHAR",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0070),  verified=False), # 64 bit pointer to a real char


#      really a wide character types

    CvInfoType(key=CvdumpTypeKey(0x0071),  name="T_WCHAR",        fmt="H",    size=2,   pointer=None,                   verified=True ), # wide char
    CvInfoType(key=CvdumpTypeKey(0x0171),  name="T_PWCHAR",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0071),  verified=False), # 16 bit pointer to a wide char
    CvInfoType(key=CvdumpTypeKey(0x0271),  name="T_PFWCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0071),  verified=False), # 16:16 far pointer to a wide char
    CvInfoType(key=CvdumpTypeKey(0x0371),  name="T_PHWCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0071),  verified=False), # 16:16 huge pointer to a wide char
    CvInfoType(key=CvdumpTypeKey(0x0471),  name="T_32PWCHAR",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0071),  verified=True ), # 32 bit pointer to a wide char
    CvInfoType(key=CvdumpTypeKey(0x0571),  name="T_32PFWCHAR",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0071),  verified=False), # 16:32 pointer to a wide char
    CvInfoType(key=CvdumpTypeKey(0x0671),  name="T_64PWCHAR",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0071),  verified=False), # 64 bit pointer to a wide char

#      really a 16-bit unicode char

    CvInfoType(key=CvdumpTypeKey(0x007a),  name="T_CHAR16",       fmt="H",    size=2,   pointer=None,                   verified=False), # 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x017a),  name="T_PCHAR16",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x007a),  verified=False), # 16 bit pointer to a 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x027a),  name="T_PFCHAR16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007a),  verified=False), # 16:16 far pointer to a 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x037a),  name="T_PHCHAR16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007a),  verified=False), # 16:16 huge pointer to a 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x047a),  name="T_32PCHAR16",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007a),  verified=False), # 32 bit pointer to a 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x057a),  name="T_32PFCHAR16",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x007a),  verified=False), # 16:32 pointer to a 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x067a),  name="T_64PCHAR16",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x007a),  verified=False), # 64 bit pointer to a 16-bit unicode char

#      really a 32-bit unicode char

    CvInfoType(key=CvdumpTypeKey(0x007b),  name="T_CHAR32",       fmt="I",    size=4,   pointer=None,                   verified=False), # 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x017b),  name="T_PCHAR32",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x007b),  verified=False), # 16 bit pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x027b),  name="T_PFCHAR32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007b),  verified=False), # 16:16 far pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x037b),  name="T_PHCHAR32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007b),  verified=False), # 16:16 huge pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x047b),  name="T_32PCHAR32",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007b),  verified=False), # 32 bit pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x057b),  name="T_32PFCHAR32",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x007b),  verified=False), # 16:32 pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x067b),  name="T_64PCHAR32",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x007b),  verified=False), # 64 bit pointer to a 32-bit unicode char


#      8-bit unicode char

    CvInfoType(key=CvdumpTypeKey(0x007c),  name="T_CHAR8",        fmt="B",    size=1,   pointer=None,                   verified=False), # 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x017c),  name="T_PCHAR8",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x007c),  verified=False), # 16 bit pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x027c),  name="T_PFCHAR8",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007c),  verified=False), # 16:16 far pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x037c),  name="T_PHCHAR8",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007c),  verified=False), # 16:16 huge pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x047c),  name="T_32PCHAR8",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007c),  verified=False), # 32 bit pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x057c),  name="T_32PFCHAR8",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x007c),  verified=False), # 16:32 pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x067c),  name="T_64PCHAR8",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x007c),  verified=False), # 64 bit pointer to a 32-bit unicode char


#      8 bit int types

    CvInfoType(key=CvdumpTypeKey(0x0068),  name="T_INT1",         fmt="b",    size=1,   pointer=None,                   verified=False), # 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0168),  name="T_PINT1",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0068),  verified=False), # 16 bit pointer to 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0268),  name="T_PFINT1",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0068),  verified=False), # 16:16 far pointer to 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0368),  name="T_PHINT1",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0068),  verified=False), # 16:16 huge pointer to 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0468),  name="T_32PINT1",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0068),  verified=False), # 32 bit pointer to 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0568),  name="T_32PFINT1",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0068),  verified=False), # 16:32 pointer to 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0668),  name="T_64PINT1",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0068),  verified=False), # 64 bit pointer to 8 bit signed int

    CvInfoType(key=CvdumpTypeKey(0x0069),  name="T_UINT1",        fmt="B",    size=1,   pointer=None,                   verified=False), # 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0169),  name="T_PUINT1",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0069),  verified=False), # 16 bit pointer to 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0269),  name="T_PFUINT1",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0069),  verified=False), # 16:16 far pointer to 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0369),  name="T_PHUINT1",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0069),  verified=False), # 16:16 huge pointer to 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0469),  name="T_32PUINT1",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0069),  verified=False), # 32 bit pointer to 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0569),  name="T_32PFUINT1",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0069),  verified=False), # 16:32 pointer to 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0669),  name="T_64PUINT1",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0069),  verified=False), # 64 bit pointer to 8 bit unsigned int


#      16 bit short types

    CvInfoType(key=CvdumpTypeKey(0x0011),  name="T_SHORT",        fmt="h",    size=2,   pointer=None,                   verified=True ), # 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0111),  name="T_PSHORT",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0011),  verified=False), # 16 bit pointer to 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0211),  name="T_PFSHORT",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0011),  verified=False), # 16:16 far pointer to 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0311),  name="T_PHSHORT",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0011),  verified=False), # 16:16 huge pointer to 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0411),  name="T_32PSHORT",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0011),  verified=True ), # 32 bit pointer to 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0511),  name="T_32PFSHORT",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0011),  verified=False), # 16:32 pointer to 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0611),  name="T_64PSHORT",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0011),  verified=False), # 64 bit pointer to 16 bit signed

    CvInfoType(key=CvdumpTypeKey(0x0021),  name="T_USHORT",       fmt="H",    size=2,   pointer=None,                   verified=True ), # 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0121),  name="T_PUSHORT",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0021),  verified=False), # 16 bit pointer to 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0221),  name="T_PFUSHORT",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0021),  verified=False), # 16:16 far pointer to 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0321),  name="T_PHUSHORT",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0021),  verified=False), # 16:16 huge pointer to 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0421),  name="T_32PUSHORT",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0021),  verified=True ), # 32 bit pointer to 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0521),  name="T_32PFUSHORT",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0021),  verified=False), # 16:32 pointer to 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0621),  name="T_64PUSHORT",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0021),  verified=False), # 64 bit pointer to 16 bit unsigned


#      16 bit int types

    CvInfoType(key=CvdumpTypeKey(0x0072),  name="T_INT2",         fmt="h",    size=2,   pointer=None,                   verified=False), # 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0172),  name="T_PINT2",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0072),  verified=False), # 16 bit pointer to 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0272),  name="T_PFINT2",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0072),  verified=False), # 16:16 far pointer to 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0372),  name="T_PHINT2",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0072),  verified=False), # 16:16 huge pointer to 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0472),  name="T_32PINT2",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0072),  verified=False), # 32 bit pointer to 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0572),  name="T_32PFINT2",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0072),  verified=False), # 16:32 pointer to 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0672),  name="T_64PINT2",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0072),  verified=False), # 64 bit pointer to 16 bit signed int

    CvInfoType(key=CvdumpTypeKey(0x0073),  name="T_UINT2",        fmt="H",    size=2,   pointer=None,                   verified=False), # 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0173),  name="T_PUINT2",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0073),  verified=False), # 16 bit pointer to 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0273),  name="T_PFUINT2",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0073),  verified=False), # 16:16 far pointer to 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0373),  name="T_PHUINT2",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0073),  verified=False), # 16:16 huge pointer to 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0473),  name="T_32PUINT2",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0073),  verified=False), # 32 bit pointer to 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0573),  name="T_32PFUINT2",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0073),  verified=False), # 16:32 pointer to 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0673),  name="T_64PUINT2",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0073),  verified=False), # 64 bit pointer to 16 bit unsigned int


#      32 bit long types

    CvInfoType(key=CvdumpTypeKey(0x0012),  name="T_LONG",         fmt="l",    size=4,   pointer=None,                   verified=True ), # 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0112),  name="T_PLONG",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0012),  verified=False), # 16 bit pointer to 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0212),  name="T_PFLONG",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0012),  verified=False), # 16:16 far pointer to 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0312),  name="T_PHLONG",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0012),  verified=False), # 16:16 huge pointer to 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0412),  name="T_32PLONG",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0012),  verified=True ), # 32 bit pointer to 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0512),  name="T_32PFLONG",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0012),  verified=False), # 16:32 pointer to 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0612),  name="T_64PLONG",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0012),  verified=False), # 64 bit pointer to 32 bit signed

    CvInfoType(key=CvdumpTypeKey(0x0022),  name="T_ULONG",        fmt="L",    size=4,   pointer=None,                   verified=True ), # 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0122),  name="T_PULONG",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0022),  verified=False), # 16 bit pointer to 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0222),  name="T_PFULONG",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0022),  verified=False), # 16:16 far pointer to 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0322),  name="T_PHULONG",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0022),  verified=False), # 16:16 huge pointer to 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0422),  name="T_32PULONG",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0022),  verified=True ), # 32 bit pointer to 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0522),  name="T_32PFULONG",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0022),  verified=False), # 16:32 pointer to 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0622),  name="T_64PULONG",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0022),  verified=False), # 64 bit pointer to 32 bit unsigned

#      32 bit int types

    CvInfoType(key=CvdumpTypeKey(0x0074),  name="T_INT4",         fmt="i",    size=4,   pointer=None,                   verified=True ), # 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0174),  name="T_PINT4",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0074),  verified=False), # 16 bit pointer to 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0274),  name="T_PFINT4",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0074),  verified=False), # 16:16 far pointer to 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0374),  name="T_PHINT4",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0074),  verified=False), # 16:16 huge pointer to 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0474),  name="T_32PINT4",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0074),  verified=True ), # 32 bit pointer to 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0574),  name="T_32PFINT4",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0074),  verified=False), # 16:32 pointer to 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0674),  name="T_64PINT4",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0074),  verified=False), # 64 bit pointer to 32 bit signed int

    CvInfoType(key=CvdumpTypeKey(0x0075),  name="T_UINT4",        fmt="I",    size=4,   pointer=None,                   verified=True ), # 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0175),  name="T_PUINT4",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0075),  verified=False), # 16 bit pointer to 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0275),  name="T_PFUINT4",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0075),  verified=False), # 16:16 far pointer to 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0375),  name="T_PHUINT4",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0075),  verified=False), # 16:16 huge pointer to 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0475),  name="T_32PUINT4",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0075),  verified=True ), # 32 bit pointer to 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0575),  name="T_32PFUINT4",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0075),  verified=False), # 16:32 pointer to 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0675),  name="T_64PUINT4",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0075),  verified=False), # 64 bit pointer to 32 bit unsigned int


#      64 bit quad types

    CvInfoType(key=CvdumpTypeKey(0x0013),  name="T_QUAD",         fmt="q",    size=8,   pointer=None,                   verified=True ), # 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0113),  name="T_PQUAD",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0013),  verified=False), # 16 bit pointer to 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0213),  name="T_PFQUAD",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0013),  verified=False), # 16:16 far pointer to 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0313),  name="T_PHQUAD",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0013),  verified=False), # 16:16 huge pointer to 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0413),  name="T_32PQUAD",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0013),  verified=True ), # 32 bit pointer to 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0513),  name="T_32PFQUAD",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0013),  verified=False), # 16:32 pointer to 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0613),  name="T_64PQUAD",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0013),  verified=False), # 64 bit pointer to 64 bit signed

    CvInfoType(key=CvdumpTypeKey(0x0023),  name="T_UQUAD",        fmt="Q",    size=8,   pointer=None,                   verified=True ), # 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0123),  name="T_PUQUAD",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0023),  verified=False), # 16 bit pointer to 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0223),  name="T_PFUQUAD",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0023),  verified=False), # 16:16 far pointer to 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0323),  name="T_PHUQUAD",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0023),  verified=False), # 16:16 huge pointer to 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0423),  name="T_32PUQUAD",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0023),  verified=True ), # 32 bit pointer to 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0523),  name="T_32PFUQUAD",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0023),  verified=False), # 16:32 pointer to 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0623),  name="T_64PUQUAD",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0023),  verified=False), # 64 bit pointer to 64 bit unsigned


#      64 bit int types

    CvInfoType(key=CvdumpTypeKey(0x0076),  name="T_INT8",         fmt="q",    size=8,   pointer=None,                   verified=False), # 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0176),  name="T_PINT8",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0076),  verified=False), # 16 bit pointer to 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0276),  name="T_PFINT8",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0076),  verified=False), # 16:16 far pointer to 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0376),  name="T_PHINT8",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0076),  verified=False), # 16:16 huge pointer to 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0476),  name="T_32PINT8",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0076),  verified=False), # 32 bit pointer to 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0576),  name="T_32PFINT8",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0076),  verified=False), # 16:32 pointer to 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0676),  name="T_64PINT8",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0076),  verified=False), # 64 bit pointer to 64 bit signed int

    CvInfoType(key=CvdumpTypeKey(0x0077),  name="T_UINT8",        fmt="Q",    size=8,   pointer=None,                   verified=False), # 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0177),  name="T_PUINT8",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0077),  verified=False), # 16 bit pointer to 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0277),  name="T_PFUINT8",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0077),  verified=False), # 16:16 far pointer to 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0377),  name="T_PHUINT8",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0077),  verified=False), # 16:16 huge pointer to 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0477),  name="T_32PUINT8",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0077),  verified=False), # 32 bit pointer to 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0577),  name="T_32PFUINT8",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0077),  verified=False), # 16:32 pointer to 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0677),  name="T_64PUINT8",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0077),  verified=False), # 64 bit pointer to 64 bit unsigned int


#      128 bit octet types

    CvInfoType(key=CvdumpTypeKey(0x0014),  name="T_OCT",          fmt="16B",  size=16,  pointer=None,                   verified=False), # 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0114),  name="T_POCT",         fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0014),  verified=False), # 16 bit pointer to 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0214),  name="T_PFOCT",        fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0014),  verified=False), # 16:16 far pointer to 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0314),  name="T_PHOCT",        fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0014),  verified=False), # 16:16 huge pointer to 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0414),  name="T_32POCT",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0014),  verified=False), # 32 bit pointer to 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0514),  name="T_32PFOCT",      fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0014),  verified=False), # 16:32 pointer to 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0614),  name="T_64POCT",       fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0014),  verified=False), # 64 bit pointer to 128 bit signed

    CvInfoType(key=CvdumpTypeKey(0x0024),  name="T_UOCT",         fmt="16B",  size=16,  pointer=None,                   verified=False), # 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0124),  name="T_PUOCT",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0024),  verified=False), # 16 bit pointer to 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0224),  name="T_PFUOCT",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0024),  verified=False), # 16:16 far pointer to 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0324),  name="T_PHUOCT",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0024),  verified=False), # 16:16 huge pointer to 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0424),  name="T_32PUOCT",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0024),  verified=False), # 32 bit pointer to 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0524),  name="T_32PFUOCT",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0024),  verified=False), # 16:32 pointer to 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0624),  name="T_64PUOCT",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0024),  verified=False), # 64 bit pointer to 128 bit unsigned


#      128 bit int types

    CvInfoType(key=CvdumpTypeKey(0x0078),  name="T_INT16",        fmt="16B",  size=16,  pointer=None,                   verified=False), # 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0178),  name="T_PINT16",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0078),  verified=False), # 16 bit pointer to 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0278),  name="T_PFINT16",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0078),  verified=False), # 16:16 far pointer to 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0378),  name="T_PHINT16",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0078),  verified=False), # 16:16 huge pointer to 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0478),  name="T_32PINT16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0078),  verified=False), # 32 bit pointer to 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0578),  name="T_32PFINT16",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0078),  verified=False), # 16:32 pointer to 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0678),  name="T_64PINT16",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0078),  verified=False), # 64 bit pointer to 128 bit signed int

    CvInfoType(key=CvdumpTypeKey(0x0079),  name="T_UINT16",       fmt="16B",  size=16,  pointer= None,   verified=False), # 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0179),  name="T_PUINT16",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0079),  verified=False), # 16 bit pointer to 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0279),  name="T_PFUINT16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0079),  verified=False), # 16:16 far pointer to 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0379),  name="T_PHUINT16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0079),  verified=False), # 16:16 huge pointer to 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0479),  name="T_32PUINT16",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0079),  verified=False), # 32 bit pointer to 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0579),  name="T_32PFUINT16",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0079),  verified=False), # 16:32 pointer to 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0679),  name="T_64PUINT16",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0079),  verified=False), # 64 bit pointer to 128 bit unsigned int


#      16 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0046),  name="T_REAL16",       fmt="2B",   size=2,   pointer=None,                   verified=False), # 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0146),  name="T_PREAL16",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0046),  verified=False), # 16 bit pointer to 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0246),  name="T_PFREAL16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0046),  verified=False), # 16:16 far pointer to 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0346),  name="T_PHREAL16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0046),  verified=False), # 16:16 huge pointer to 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0446),  name="T_32PREAL16",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0046),  verified=False), # 32 bit pointer to 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0546),  name="T_32PFREAL16",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0046),  verified=False), # 16:32 pointer to 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0646),  name="T_64PREAL16",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0046),  verified=False), # 64 bit pointer to 16 bit real


#      32 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0040),  name="T_REAL32",       fmt="f",    size=4,   pointer=None,                   verified=True ), # 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0140),  name="T_PREAL32",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0040),  verified=False), # 16 bit pointer to 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0240),  name="T_PFREAL32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0040),  verified=False), # 16:16 far pointer to 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0340),  name="T_PHREAL32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0040),  verified=False), # 16:16 huge pointer to 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0440),  name="T_32PREAL32",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0040),  verified=True ), # 32 bit pointer to 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0540),  name="T_32PFREAL32",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0040),  verified=False), # 16:32 pointer to 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0640),  name="T_64PREAL32",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0040),  verified=False), # 64 bit pointer to 32 bit real


#      32 bit partial-precision real types

    CvInfoType(key=CvdumpTypeKey(0x0045),  name="T_REAL32PP",     fmt="4B",   size=4,   pointer=None,                   verified=False), # 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0145),  name="T_PREAL32PP",    fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0045),  verified=False), # 16 bit pointer to 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0245),  name="T_PFREAL32PP",   fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0045),  verified=False), # 16:16 far pointer to 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0345),  name="T_PHREAL32PP",   fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0045),  verified=False), # 16:16 huge pointer to 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0445),  name="T_32PREAL32PP",  fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0045),  verified=False), # 32 bit pointer to 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0545),  name="T_32PFREAL32PP", fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0045),  verified=False), # 16:32 pointer to 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0645),  name="T_64PREAL32PP",  fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0045),  verified=False), # 64 bit pointer to 32 bit PP real


#      48 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0044),  name="T_REAL48",       fmt="6B",   size=6,   pointer=None,                   verified=False), # 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0144),  name="T_PREAL48",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0044),  verified=False), # 16 bit pointer to 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0244),  name="T_PFREAL48",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0044),  verified=False), # 16:16 far pointer to 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0344),  name="T_PHREAL48",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0044),  verified=False), # 16:16 huge pointer to 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0444),  name="T_32PREAL48",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0044),  verified=False), # 32 bit pointer to 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0544),  name="T_32PFREAL48",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0044),  verified=False), # 16:32 pointer to 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0644),  name="T_64PREAL48",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0044),  verified=False), # 64 bit pointer to 48 bit real


#      64 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0041),  name="T_REAL64",       fmt="d",    size=8,   pointer=None,                   verified=True ), # 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0141),  name="T_PREAL64",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0041),  verified=False), # 16 bit pointer to 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0241),  name="T_PFREAL64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0041),  verified=False), # 16:16 far pointer to 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0341),  name="T_PHREAL64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0041),  verified=False), # 16:16 huge pointer to 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0441),  name="T_32PREAL64",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0041),  verified=True ), # 32 bit pointer to 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0541),  name="T_32PFREAL64",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0041),  verified=False), # 16:32 pointer to 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0641),  name="T_64PREAL64",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0041),  verified=False), # 64 bit pointer to 64 bit real


#      80 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0042),  name="T_REAL80",       fmt="10B",  size=10,  pointer=None,                   verified=False), # 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0142),  name="T_PREAL80",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0042),  verified=False), # 16 bit pointer to 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0242),  name="T_PFREAL80",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0042),  verified=False), # 16:16 far pointer to 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0342),  name="T_PHREAL80",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0042),  verified=False), # 16:16 huge pointer to 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0442),  name="T_32PREAL80",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0042),  verified=False), # 32 bit pointer to 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0542),  name="T_32PFREAL80",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0042),  verified=False), # 16:32 pointer to 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0642),  name="T_64PREAL80",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0042),  verified=False), # 64 bit pointer to 80 bit real


#      128 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0043),  name="T_REAL128",      fmt="16B",  size=16,  pointer=None,                   verified=False), # 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0143),  name="T_PREAL128",     fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0043),  verified=False), # 16 bit pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0243),  name="T_PFREAL128",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0043),  verified=False), # 16:16 far pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0343),  name="T_PHREAL128",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0043),  verified=False), # 16:16 huge pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0443),  name="T_32PREAL128",   fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0043),  verified=False), # 32 bit pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0543),  name="T_32PFREAL128",  fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0043),  verified=False), # 16:32 pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0643),  name="T_64PREAL128",   fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0043),  verified=False), # 64 bit pointer to 128 bit real


#      32 bit complex types

    CvInfoType(key=CvdumpTypeKey(0x0050),  name="T_CPLX32",       fmt="4B",   size=4,   pointer=None,                   verified=False), # 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0150),  name="T_PCPLX32",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0050),  verified=False), # 16 bit pointer to 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0250),  name="T_PFCPLX32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0050),  verified=False), # 16:16 far pointer to 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0350),  name="T_PHCPLX32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0050),  verified=False), # 16:16 huge pointer to 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0450),  name="T_32PCPLX32",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0050),  verified=False), # 32 bit pointer to 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0550),  name="T_32PFCPLX32",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0050),  verified=False), # 16:32 pointer to 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0650),  name="T_64PCPLX32",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0050),  verified=False), # 64 bit pointer to 32 bit complex


#      64 bit complex types

    CvInfoType(key=CvdumpTypeKey(0x0051),  name="T_CPLX64",       fmt="F",    size=8,   pointer=None,                   verified=False), # 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0151),  name="T_PCPLX64",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0051),  verified=False), # 16 bit pointer to 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0251),  name="T_PFCPLX64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0051),  verified=False), # 16:16 far pointer to 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0351),  name="T_PHCPLX64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0051),  verified=False), # 16:16 huge pointer to 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0451),  name="T_32PCPLX64",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0051),  verified=False), # 32 bit pointer to 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0551),  name="T_32PFCPLX64",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0051),  verified=False), # 16:32 pointer to 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0651),  name="T_64PCPLX64",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0051),  verified=False), # 64 bit pointer to 64 bit complex


#      80 bit complex types

    CvInfoType(key=CvdumpTypeKey(0x0052),  name="T_CPLX80",       fmt="10B",  size=10,  pointer=None,                   verified=False), # 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0152),  name="T_PCPLX80",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0052),  verified=False), # 16 bit pointer to 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0252),  name="T_PFCPLX80",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0052),  verified=False), # 16:16 far pointer to 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0352),  name="T_PHCPLX80",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0052),  verified=False), # 16:16 huge pointer to 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0452),  name="T_32PCPLX80",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0052),  verified=False), # 32 bit pointer to 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0552),  name="T_32PFCPLX80",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0052),  verified=False), # 16:32 pointer to 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0652),  name="T_64PCPLX80",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0052),  verified=False), # 64 bit pointer to 80 bit complex


#      128 bit complex types

    CvInfoType(key=CvdumpTypeKey(0x0053),  name="T_CPLX128",      fmt="D",    size=16,  pointer=None,                   verified=False), # 128 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0153),  name="T_PCPLX128",     fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0053),  verified=False), # 16 bit pointer to 128 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0253),  name="T_PFCPLX128",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0053),  verified=False), # 16:16 far pointer to 128 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0353),  name="T_PHCPLX128",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0053),  verified=False), # 16:16 huge pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0453),  name="T_32PCPLX128",   fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0053),  verified=False), # 32 bit pointer to 128 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0553),  name="T_32PFCPLX128",  fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0053),  verified=False), # 16:32 pointer to 128 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0653),  name="T_64PCPLX128",   fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0053),  verified=False), # 64 bit pointer to 128 bit complex


#      boolean types

    CvInfoType(key=CvdumpTypeKey(0x0030),  name="T_BOOL08",       fmt="B",    size=1,   pointer=None,                   verified=False), # 8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0130),  name="T_PBOOL08",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0030),  verified=False), # 16 bit pointer to  8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0230),  name="T_PFBOOL08",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0030),  verified=False), # 16:16 far pointer to  8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0330),  name="T_PHBOOL08",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0030),  verified=False), # 16:16 huge pointer to  8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0430),  name="T_32PBOOL08",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0030),  verified=False), # 32 bit pointer to 8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0530),  name="T_32PFBOOL08",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0030),  verified=False), # 16:32 pointer to 8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0630),  name="T_64PBOOL08",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0030),  verified=False), # 64 bit pointer to 8 bit boolean

    CvInfoType(key=CvdumpTypeKey(0x0031),  name="T_BOOL16",       fmt="H",    size=2,   pointer=None,                   verified=False), # 16 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0131),  name="T_PBOOL16",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0031),  verified=False), # 16 bit pointer to 16 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0231),  name="T_PFBOOL16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0031),  verified=False), # 16:16 far pointer to 16 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0331),  name="T_PHBOOL16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0031),  verified=False), # 16:16 huge pointer to 16 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0431),  name="T_32PBOOL16",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0031),  verified=False), # 32 bit pointer to 18 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0531),  name="T_32PFBOOL16",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0031),  verified=False), # 16:32 pointer to 16 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0631),  name="T_64PBOOL16",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0031),  verified=False), # 64 bit pointer to 18 bit boolean

    CvInfoType(key=CvdumpTypeKey(0x0032),  name="T_BOOL32",       fmt="I",    size=4,   pointer=None,                   verified=False), # 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0132),  name="T_PBOOL32",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0032),  verified=False), # 16 bit pointer to 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0232),  name="T_PFBOOL32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0032),  verified=False), # 16:16 far pointer to 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0332),  name="T_PHBOOL32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0032),  verified=False), # 16:16 huge pointer to 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0432),  name="T_32PBOOL32",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0032),  verified=False), # 32 bit pointer to 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0532),  name="T_32PFBOOL32",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0032),  verified=False), # 16:32 pointer to 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0632),  name="T_64PBOOL32",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0032),  verified=False), # 64 bit pointer to 32 bit boolean

    CvInfoType(key=CvdumpTypeKey(0x0033),  name="T_BOOL64",       fmt="Q",    size=8,   pointer=None,                   verified=False), # 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0133),  name="T_PBOOL64",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0033),  verified=False), # 16 bit pointer to 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0233),  name="T_PFBOOL64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0033),  verified=False), # 16:16 far pointer to 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0333),  name="T_PHBOOL64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0033),  verified=False), # 16:16 huge pointer to 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0433),  name="T_32PBOOL64",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0033),  verified=False), # 32 bit pointer to 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0533),  name="T_32PFBOOL64",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0033),  verified=False), # 16:32 pointer to 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0633),  name="T_64PBOOL64",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0033),  verified=False), # 64 bit pointer to 64 bit boolean


#      ???

    CvInfoType(key=CvdumpTypeKey(0x01f0),  name="T_NCVPTR",       fmt="",     size=0,   pointer=None,                   verified=False), # CV Internal type for created near pointers
    CvInfoType(key=CvdumpTypeKey(0x02f0),  name="T_FCVPTR",       fmt="",     size=0,   pointer=None,                   verified=False), # CV Internal type for created far pointers
    CvInfoType(key=CvdumpTypeKey(0x03f0),  name="T_HCVPTR",       fmt="",     size=0,   pointer=None,                   verified=False), # CV Internal type for created huge pointers
    CvInfoType(key=CvdumpTypeKey(0x04f0),  name="T_32NCVPTR",     fmt="",     size=0,   pointer=None,                   verified=False), # CV Internal type for created near 32-bit pointers
    CvInfoType(key=CvdumpTypeKey(0x05f0),  name="T_32FCVPTR",     fmt="",     size=0,   pointer=None,                   verified=False), # CV Internal type for created far 32-bit pointers
    CvInfoType(key=CvdumpTypeKey(0x06f0),  name="T_64NCVPTR",     fmt="",     size=0,   pointer=None,                   verified=False), # CV Internal type for created near 64-bit pointers
)
# fmt: on


class CVInfoTypeEnum(CvdumpTypeKey, Enum):
    # fmt: off
    T_NOTYPE      = CvdumpTypeKey(0x0000)
    T_ABS         = CvdumpTypeKey(0x0001)
    T_SEGMENT     = CvdumpTypeKey(0x0002)
    T_VOID        = CvdumpTypeKey(0x0003)
    T_CURRENCY    = CvdumpTypeKey(0x0004)
    T_NBASICSTR   = CvdumpTypeKey(0x0005)
    T_FBASICSTR   = CvdumpTypeKey(0x0006)
    T_NOTTRANS    = CvdumpTypeKey(0x0007)
    T_HRESULT     = CvdumpTypeKey(0x0008)
    T_CHAR        = CvdumpTypeKey(0x0010)
    T_SHORT       = CvdumpTypeKey(0x0011)
    T_LONG        = CvdumpTypeKey(0x0012)
    T_QUAD        = CvdumpTypeKey(0x0013)
    T_OCT         = CvdumpTypeKey(0x0014)
    T_UCHAR       = CvdumpTypeKey(0x0020)
    T_USHORT      = CvdumpTypeKey(0x0021)
    T_ULONG       = CvdumpTypeKey(0x0022)
    T_UQUAD       = CvdumpTypeKey(0x0023)
    T_UOCT        = CvdumpTypeKey(0x0024)
    T_BOOL08      = CvdumpTypeKey(0x0030)
    T_BOOL16      = CvdumpTypeKey(0x0031)
    T_BOOL32      = CvdumpTypeKey(0x0032)
    T_BOOL64      = CvdumpTypeKey(0x0033)
    T_REAL32      = CvdumpTypeKey(0x0040)
    T_REAL64      = CvdumpTypeKey(0x0041)
    T_REAL80      = CvdumpTypeKey(0x0042)
    T_REAL128     = CvdumpTypeKey(0x0043)
    T_REAL48      = CvdumpTypeKey(0x0044)
    T_REAL32PP    = CvdumpTypeKey(0x0045)
    T_REAL16      = CvdumpTypeKey(0x0046)
    T_CPLX32      = CvdumpTypeKey(0x0050)
    T_CPLX64      = CvdumpTypeKey(0x0051)
    T_CPLX80      = CvdumpTypeKey(0x0052)
    T_CPLX128     = CvdumpTypeKey(0x0053)
    T_BIT         = CvdumpTypeKey(0x0060)
    T_PASCHAR     = CvdumpTypeKey(0x0061)
    T_BOOL32FF    = CvdumpTypeKey(0x0062)
    T_INT1        = CvdumpTypeKey(0x0068)
    T_UINT1       = CvdumpTypeKey(0x0069)
    T_RCHAR       = CvdumpTypeKey(0x0070)
    T_WCHAR       = CvdumpTypeKey(0x0071)
    T_INT2        = CvdumpTypeKey(0x0072)
    T_UINT2       = CvdumpTypeKey(0x0073)
    T_INT4        = CvdumpTypeKey(0x0074)
    T_UINT4       = CvdumpTypeKey(0x0075)
    T_INT8        = CvdumpTypeKey(0x0076)
    T_UINT8       = CvdumpTypeKey(0x0077)
    T_INT16       = CvdumpTypeKey(0x0078)
    T_UINT16      = CvdumpTypeKey(0x0079)
    T_CHAR16      = CvdumpTypeKey(0x007a)
    T_CHAR32      = CvdumpTypeKey(0x007b)
    T_CHAR8       = CvdumpTypeKey(0x007c)
    T_PVOID       = CvdumpTypeKey(0x0103)
    T_PCHAR       = CvdumpTypeKey(0x0110)
    T_PSHORT      = CvdumpTypeKey(0x0111)
    T_PLONG       = CvdumpTypeKey(0x0112)
    T_PQUAD       = CvdumpTypeKey(0x0113)
    T_POCT        = CvdumpTypeKey(0x0114)
    T_PUCHAR      = CvdumpTypeKey(0x0120)
    T_PUSHORT     = CvdumpTypeKey(0x0121)
    T_PULONG      = CvdumpTypeKey(0x0122)
    T_PUQUAD      = CvdumpTypeKey(0x0123)
    T_PUOCT       = CvdumpTypeKey(0x0124)
    T_PBOOL08     = CvdumpTypeKey(0x0130)
    T_PBOOL16     = CvdumpTypeKey(0x0131)
    T_PBOOL32     = CvdumpTypeKey(0x0132)
    T_PBOOL64     = CvdumpTypeKey(0x0133)
    T_PREAL32     = CvdumpTypeKey(0x0140)
    T_PREAL64     = CvdumpTypeKey(0x0141)
    T_PREAL80     = CvdumpTypeKey(0x0142)
    T_PREAL128    = CvdumpTypeKey(0x0143)
    T_PREAL48     = CvdumpTypeKey(0x0144)
    T_PREAL32PP   = CvdumpTypeKey(0x0145)
    T_PREAL16     = CvdumpTypeKey(0x0146)
    T_PCPLX32     = CvdumpTypeKey(0x0150)
    T_PCPLX64     = CvdumpTypeKey(0x0151)
    T_PCPLX80     = CvdumpTypeKey(0x0152)
    T_PCPLX128    = CvdumpTypeKey(0x0153)
    T_PINT1       = CvdumpTypeKey(0x0168)
    T_PUINT1      = CvdumpTypeKey(0x0169)
    T_PRCHAR      = CvdumpTypeKey(0x0170)
    T_PWCHAR      = CvdumpTypeKey(0x0171)
    T_PINT2       = CvdumpTypeKey(0x0172)
    T_PUINT2      = CvdumpTypeKey(0x0173)
    T_PINT4       = CvdumpTypeKey(0x0174)
    T_PUINT4      = CvdumpTypeKey(0x0175)
    T_PINT8       = CvdumpTypeKey(0x0176)
    T_PUINT8      = CvdumpTypeKey(0x0177)
    T_PINT16      = CvdumpTypeKey(0x0178)
    T_PUINT16     = CvdumpTypeKey(0x0179)
    T_PCHAR16     = CvdumpTypeKey(0x017a)
    T_PCHAR32     = CvdumpTypeKey(0x017b)
    T_PCHAR8      = CvdumpTypeKey(0x017c)
    T_NCVPTR      = CvdumpTypeKey(0x01f0)
    T_PFVOID      = CvdumpTypeKey(0x0203)
    T_PFCHAR      = CvdumpTypeKey(0x0210)
    T_PFSHORT     = CvdumpTypeKey(0x0211)
    T_PFLONG      = CvdumpTypeKey(0x0212)
    T_PFQUAD      = CvdumpTypeKey(0x0213)
    T_PFOCT       = CvdumpTypeKey(0x0214)
    T_PFUCHAR     = CvdumpTypeKey(0x0220)
    T_PFUSHORT    = CvdumpTypeKey(0x0221)
    T_PFULONG     = CvdumpTypeKey(0x0222)
    T_PFUQUAD     = CvdumpTypeKey(0x0223)
    T_PFUOCT      = CvdumpTypeKey(0x0224)
    T_PFBOOL08    = CvdumpTypeKey(0x0230)
    T_PFBOOL16    = CvdumpTypeKey(0x0231)
    T_PFBOOL32    = CvdumpTypeKey(0x0232)
    T_PFBOOL64    = CvdumpTypeKey(0x0233)
    T_PFREAL32    = CvdumpTypeKey(0x0240)
    T_PFREAL64    = CvdumpTypeKey(0x0241)
    T_PFREAL80    = CvdumpTypeKey(0x0242)
    T_PFREAL128   = CvdumpTypeKey(0x0243)
    T_PFREAL48    = CvdumpTypeKey(0x0244)
    T_PFREAL32PP  = CvdumpTypeKey(0x0245)
    T_PFREAL16    = CvdumpTypeKey(0x0246)
    T_PFCPLX32    = CvdumpTypeKey(0x0250)
    T_PFCPLX64    = CvdumpTypeKey(0x0251)
    T_PFCPLX80    = CvdumpTypeKey(0x0252)
    T_PFCPLX128   = CvdumpTypeKey(0x0253)
    T_PFINT1      = CvdumpTypeKey(0x0268)
    T_PFUINT1     = CvdumpTypeKey(0x0269)
    T_PFRCHAR     = CvdumpTypeKey(0x0270)
    T_PFWCHAR     = CvdumpTypeKey(0x0271)
    T_PFINT2      = CvdumpTypeKey(0x0272)
    T_PFUINT2     = CvdumpTypeKey(0x0273)
    T_PFINT4      = CvdumpTypeKey(0x0274)
    T_PFUINT4     = CvdumpTypeKey(0x0275)
    T_PFINT8      = CvdumpTypeKey(0x0276)
    T_PFUINT8     = CvdumpTypeKey(0x0277)
    T_PFINT16     = CvdumpTypeKey(0x0278)
    T_PFUINT16    = CvdumpTypeKey(0x0279)
    T_PFCHAR16    = CvdumpTypeKey(0x027a)
    T_PFCHAR32    = CvdumpTypeKey(0x027b)
    T_PFCHAR8     = CvdumpTypeKey(0x027c)
    T_FCVPTR      = CvdumpTypeKey(0x02f0)
    T_PHVOID      = CvdumpTypeKey(0x0303)
    T_PHCHAR      = CvdumpTypeKey(0x0310)
    T_PHSHORT     = CvdumpTypeKey(0x0311)
    T_PHLONG      = CvdumpTypeKey(0x0312)
    T_PHQUAD      = CvdumpTypeKey(0x0313)
    T_PHOCT       = CvdumpTypeKey(0x0314)
    T_PHUCHAR     = CvdumpTypeKey(0x0320)
    T_PHUSHORT    = CvdumpTypeKey(0x0321)
    T_PHULONG     = CvdumpTypeKey(0x0322)
    T_PHUQUAD     = CvdumpTypeKey(0x0323)
    T_PHUOCT      = CvdumpTypeKey(0x0324)
    T_PHBOOL08    = CvdumpTypeKey(0x0330)
    T_PHBOOL16    = CvdumpTypeKey(0x0331)
    T_PHBOOL32    = CvdumpTypeKey(0x0332)
    T_PHBOOL64    = CvdumpTypeKey(0x0333)
    T_PHREAL32    = CvdumpTypeKey(0x0340)
    T_PHREAL64    = CvdumpTypeKey(0x0341)
    T_PHREAL80    = CvdumpTypeKey(0x0342)
    T_PHREAL128   = CvdumpTypeKey(0x0343)
    T_PHREAL48    = CvdumpTypeKey(0x0344)
    T_PHREAL32PP  = CvdumpTypeKey(0x0345)
    T_PHREAL16    = CvdumpTypeKey(0x0346)
    T_PHCPLX32    = CvdumpTypeKey(0x0350)
    T_PHCPLX64    = CvdumpTypeKey(0x0351)
    T_PHCPLX80    = CvdumpTypeKey(0x0352)
    T_PHCPLX128   = CvdumpTypeKey(0x0353)
    T_PHINT1      = CvdumpTypeKey(0x0368)
    T_PHUINT1     = CvdumpTypeKey(0x0369)
    T_PHRCHAR     = CvdumpTypeKey(0x0370)
    T_PHWCHAR     = CvdumpTypeKey(0x0371)
    T_PHINT2      = CvdumpTypeKey(0x0372)
    T_PHUINT2     = CvdumpTypeKey(0x0373)
    T_PHINT4      = CvdumpTypeKey(0x0374)
    T_PHUINT4     = CvdumpTypeKey(0x0375)
    T_PHINT8      = CvdumpTypeKey(0x0376)
    T_PHUINT8     = CvdumpTypeKey(0x0377)
    T_PHINT16     = CvdumpTypeKey(0x0378)
    T_PHUINT16    = CvdumpTypeKey(0x0379)
    T_PHCHAR16    = CvdumpTypeKey(0x037a)
    T_PHCHAR32    = CvdumpTypeKey(0x037b)
    T_PHCHAR8     = CvdumpTypeKey(0x037c)
    T_HCVPTR      = CvdumpTypeKey(0x03f0)
    T_32PVOID     = CvdumpTypeKey(0x0403)
    T_32PHRESULT  = CvdumpTypeKey(0x0408)
    T_32PCHAR     = CvdumpTypeKey(0x0410)
    T_32PSHORT    = CvdumpTypeKey(0x0411)
    T_32PLONG     = CvdumpTypeKey(0x0412)
    T_32PQUAD     = CvdumpTypeKey(0x0413)
    T_32POCT      = CvdumpTypeKey(0x0414)
    T_32PUCHAR    = CvdumpTypeKey(0x0420)
    T_32PUSHORT   = CvdumpTypeKey(0x0421)
    T_32PULONG    = CvdumpTypeKey(0x0422)
    T_32PUQUAD    = CvdumpTypeKey(0x0423)
    T_32PUOCT     = CvdumpTypeKey(0x0424)
    T_32PBOOL08   = CvdumpTypeKey(0x0430)
    T_32PBOOL16   = CvdumpTypeKey(0x0431)
    T_32PBOOL32   = CvdumpTypeKey(0x0432)
    T_32PBOOL64   = CvdumpTypeKey(0x0433)
    T_32PREAL32   = CvdumpTypeKey(0x0440)
    T_32PREAL64   = CvdumpTypeKey(0x0441)
    T_32PREAL80   = CvdumpTypeKey(0x0442)
    T_32PREAL128  = CvdumpTypeKey(0x0443)
    T_32PREAL48   = CvdumpTypeKey(0x0444)
    T_32PREAL32PP = CvdumpTypeKey(0x0445)
    T_32PREAL16   = CvdumpTypeKey(0x0446)
    T_32PCPLX32   = CvdumpTypeKey(0x0450)
    T_32PCPLX64   = CvdumpTypeKey(0x0451)
    T_32PCPLX80   = CvdumpTypeKey(0x0452)
    T_32PCPLX128  = CvdumpTypeKey(0x0453)
    T_32PINT1     = CvdumpTypeKey(0x0468)
    T_32PUINT1    = CvdumpTypeKey(0x0469)
    T_32PRCHAR    = CvdumpTypeKey(0x0470)
    T_32PWCHAR    = CvdumpTypeKey(0x0471)
    T_32PINT2     = CvdumpTypeKey(0x0472)
    T_32PUINT2    = CvdumpTypeKey(0x0473)
    T_32PINT4     = CvdumpTypeKey(0x0474)
    T_32PUINT4    = CvdumpTypeKey(0x0475)
    T_32PINT8     = CvdumpTypeKey(0x0476)
    T_32PUINT8    = CvdumpTypeKey(0x0477)
    T_32PINT16    = CvdumpTypeKey(0x0478)
    T_32PUINT16   = CvdumpTypeKey(0x0479)
    T_32PCHAR16   = CvdumpTypeKey(0x047a)
    T_32PCHAR32   = CvdumpTypeKey(0x047b)
    T_32PCHAR8    = CvdumpTypeKey(0x047c)
    T_32NCVPTR    = CvdumpTypeKey(0x04f0)
    T_32PFVOID    = CvdumpTypeKey(0x0503)
    T_32PFCHAR    = CvdumpTypeKey(0x0510)
    T_32PFSHORT   = CvdumpTypeKey(0x0511)
    T_32PFLONG    = CvdumpTypeKey(0x0512)
    T_32PFQUAD    = CvdumpTypeKey(0x0513)
    T_32PFOCT     = CvdumpTypeKey(0x0514)
    T_32PFUCHAR   = CvdumpTypeKey(0x0520)
    T_32PFUSHORT  = CvdumpTypeKey(0x0521)
    T_32PFULONG   = CvdumpTypeKey(0x0522)
    T_32PFUQUAD   = CvdumpTypeKey(0x0523)
    T_32PFUOCT    = CvdumpTypeKey(0x0524)
    T_32PFBOOL08  = CvdumpTypeKey(0x0530)
    T_32PFBOOL16  = CvdumpTypeKey(0x0531)
    T_32PFBOOL32  = CvdumpTypeKey(0x0532)
    T_32PFBOOL64  = CvdumpTypeKey(0x0533)
    T_32PFREAL32  = CvdumpTypeKey(0x0540)
    T_32PFREAL64  = CvdumpTypeKey(0x0541)
    T_32PFREAL80  = CvdumpTypeKey(0x0542)
    T_32PFREAL128 = CvdumpTypeKey(0x0543)
    T_32PFREAL48  = CvdumpTypeKey(0x0544)
    T_32PFREAL32PP= CvdumpTypeKey(0x0545)
    T_32PFREAL16  = CvdumpTypeKey(0x0546)
    T_32PFCPLX32  = CvdumpTypeKey(0x0550)
    T_32PFCPLX64  = CvdumpTypeKey(0x0551)
    T_32PFCPLX80  = CvdumpTypeKey(0x0552)
    T_32PFCPLX128 = CvdumpTypeKey(0x0553)
    T_32PFINT1    = CvdumpTypeKey(0x0568)
    T_32PFUINT1   = CvdumpTypeKey(0x0569)
    T_32PFRCHAR   = CvdumpTypeKey(0x0570)
    T_32PFWCHAR   = CvdumpTypeKey(0x0571)
    T_32PFINT2    = CvdumpTypeKey(0x0572)
    T_32PFUINT2   = CvdumpTypeKey(0x0573)
    T_32PFINT4    = CvdumpTypeKey(0x0574)
    T_32PFUINT4   = CvdumpTypeKey(0x0575)
    T_32PFINT8    = CvdumpTypeKey(0x0576)
    T_32PFUINT8   = CvdumpTypeKey(0x0577)
    T_32PFINT16   = CvdumpTypeKey(0x0578)
    T_32PFUINT16  = CvdumpTypeKey(0x0579)
    T_32PFCHAR16  = CvdumpTypeKey(0x057a)
    T_32PFCHAR32  = CvdumpTypeKey(0x057b)
    T_32PFCHAR8   = CvdumpTypeKey(0x057c)
    T_32FCVPTR    = CvdumpTypeKey(0x05f0)
    T_64PVOID     = CvdumpTypeKey(0x0603)
    T_64PHRESULT  = CvdumpTypeKey(0x0608)
    T_64PCHAR     = CvdumpTypeKey(0x0610)
    T_64PSHORT    = CvdumpTypeKey(0x0611)
    T_64PLONG     = CvdumpTypeKey(0x0612)
    T_64PQUAD     = CvdumpTypeKey(0x0613)
    T_64POCT      = CvdumpTypeKey(0x0614)
    T_64PUCHAR    = CvdumpTypeKey(0x0620)
    T_64PUSHORT   = CvdumpTypeKey(0x0621)
    T_64PULONG    = CvdumpTypeKey(0x0622)
    T_64PUQUAD    = CvdumpTypeKey(0x0623)
    T_64PUOCT     = CvdumpTypeKey(0x0624)
    T_64PBOOL08   = CvdumpTypeKey(0x0630)
    T_64PBOOL16   = CvdumpTypeKey(0x0631)
    T_64PBOOL32   = CvdumpTypeKey(0x0632)
    T_64PBOOL64   = CvdumpTypeKey(0x0633)
    T_64PREAL32   = CvdumpTypeKey(0x0640)
    T_64PREAL64   = CvdumpTypeKey(0x0641)
    T_64PREAL80   = CvdumpTypeKey(0x0642)
    T_64PREAL128  = CvdumpTypeKey(0x0643)
    T_64PREAL48   = CvdumpTypeKey(0x0644)
    T_64PREAL32PP = CvdumpTypeKey(0x0645)
    T_64PREAL16   = CvdumpTypeKey(0x0646)
    T_64PCPLX32   = CvdumpTypeKey(0x0650)
    T_64PCPLX64   = CvdumpTypeKey(0x0651)
    T_64PCPLX80   = CvdumpTypeKey(0x0652)
    T_64PCPLX128  = CvdumpTypeKey(0x0653)
    T_64PINT1     = CvdumpTypeKey(0x0668)
    T_64PUINT1    = CvdumpTypeKey(0x0669)
    T_64PRCHAR    = CvdumpTypeKey(0x0670)
    T_64PWCHAR    = CvdumpTypeKey(0x0671)
    T_64PINT2     = CvdumpTypeKey(0x0672)
    T_64PUINT2    = CvdumpTypeKey(0x0673)
    T_64PINT4     = CvdumpTypeKey(0x0674)
    T_64PUINT4    = CvdumpTypeKey(0x0675)
    T_64PINT8     = CvdumpTypeKey(0x0676)
    T_64PUINT8    = CvdumpTypeKey(0x0677)
    T_64PINT16    = CvdumpTypeKey(0x0678)
    T_64PUINT16   = CvdumpTypeKey(0x0679)
    T_64PCHAR16   = CvdumpTypeKey(0x067a)
    T_64PCHAR32   = CvdumpTypeKey(0x067b)
    T_64PCHAR8    = CvdumpTypeKey(0x067c)
    T_64NCVPTR    = CvdumpTypeKey(0x06f0)
    # fmt: on


CvdumpTypeMap = MappingProxyType({cv.key: cv for cv in _CVINFO_TYPES})


def scalar_type_signed(key: CvdumpTypeKey) -> bool:
    return key in (
        0x0010,
        0x0068,
        0x0011,
        0x0072,
        0x0012,
        0x0074,
        0x0013,
        0x0076,
        0x0014,
        0x0078,
        0x0070,
    )
