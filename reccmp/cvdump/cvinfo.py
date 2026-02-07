"""Type enum modified from cvinfo.h released under MIT license.
https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h
See `LICENSE.cvdump.txt` for details.
"""

from enum import Enum
from types import MappingProxyType, new_class
from typing import NamedTuple


class CvdumpTypeKey(int):
    pass


def cvdump_type_is_scalar(key: CvdumpTypeKey) -> bool:
    return key < 0x1000


def normalize_type_id(key: str) -> CvdumpTypeKey:
    """Helper for TYPES parsing to ensure a consistent format.
    If key begins with "T_" it is a built-in type.
    Else it is a hex string. We prefer lower case letters and
    no leading zeroes. (UDT identifier pads to 8 characters.)"""
    if key[0] == "0":
        return CvdumpTypeKey(int(key, 16))
        # return f"0x{key[-4:].lower()}"

    # Should cover both "T_" and "???" cases.
    return CvdumpTypeKey(int(key[-5:-1], 16))
    # Remove numeric value for "T_" type. We don't use this.
    # return key.partition("(")[0]


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
    weird: bool
    """If we encounter this type, log a message about it for potential debugging."""


# fmt: off
_CVINFO_TYPES = (

#      Special Types

    CvInfoType(key=CvdumpTypeKey(0x0000),  name="T_NOTYPE",       fmt="",     size=0,   pointer=None,                   weird=False), # uncharacterized type (no type)
    CvInfoType(key=CvdumpTypeKey(0x0001),  name="T_ABS",          fmt="",     size=0,   pointer=None,                   weird=True ), # absolute symbol
    CvInfoType(key=CvdumpTypeKey(0x0002),  name="T_SEGMENT",      fmt="",     size=0,   pointer=None,                   weird=True ), # segment type
    CvInfoType(key=CvdumpTypeKey(0x0003),  name="T_VOID",         fmt="",     size=0,   pointer=None,                   weird=False), # void
    CvInfoType(key=CvdumpTypeKey(0x0008),  name="T_HRESULT",      fmt="I",    size=4,   pointer=None,                   weird=False), # OLE/COM HRESULT
    CvInfoType(key=CvdumpTypeKey(0x0408),  name="T_32PHRESULT",   fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0008),  weird=False), # OLE/COM HRESULT __ptr32 *
    CvInfoType(key=CvdumpTypeKey(0x0608),  name="T_64PHRESULT",   fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0008),  weird=True ), # OLE/COM HRESULT __ptr64 *

    CvInfoType(key=CvdumpTypeKey(0x0103),  name="T_PVOID",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0003),  weird=True ), # near pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0203),  name="T_PFVOID",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0003),  weird=True ), # far pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0303),  name="T_PHVOID",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0003),  weird=True ), # huge pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0403),  name="T_32PVOID",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0003),  weird=False), # 32 bit pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0503),  name="T_32PFVOID",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0003),  weird=True ), # 16:32 pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0603),  name="T_64PVOID",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0003),  weird=True ), # 64 bit pointer to void
    CvInfoType(key=CvdumpTypeKey(0x0004),  name="T_CURRENCY",     fmt="",     size=0,   pointer=None,                   weird=True ), # BASIC 8 byte currency value
    CvInfoType(key=CvdumpTypeKey(0x0005),  name="T_NBASICSTR",    fmt="",     size=0,   pointer=None,                   weird=True ), # Near BASIC string
    CvInfoType(key=CvdumpTypeKey(0x0006),  name="T_FBASICSTR",    fmt="",     size=0,   pointer=None,                   weird=True ), # Far BASIC string
    CvInfoType(key=CvdumpTypeKey(0x0007),  name="T_NOTTRANS",     fmt="",     size=0,   pointer=None,                   weird=True ), # type not translated by cvpack
    CvInfoType(key=CvdumpTypeKey(0x0060),  name="T_BIT",          fmt="",     size=0,   pointer=None,                   weird=True ), # bit
    CvInfoType(key=CvdumpTypeKey(0x0061),  name="T_PASCHAR",      fmt="",     size=0,   pointer=None,                   weird=True ), # Pascal CHAR
    CvInfoType(key=CvdumpTypeKey(0x0062),  name="T_BOOL32FF",     fmt="i",    size=4,   pointer=None,                   weird=True ), # 32-bit BOOL where true is 0xffffffff


#      Character types

    CvInfoType(key=CvdumpTypeKey(0x0010),  name="T_CHAR",         fmt="b",    size=1,   pointer=None,                   weird=False), # 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0110),  name="T_PCHAR",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0010),  weird=True ), # 16 bit pointer to 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0210),  name="T_PFCHAR",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0010),  weird=True ), # 16:16 far pointer to 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0310),  name="T_PHCHAR",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0010),  weird=True ), # 16:16 huge pointer to 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0410),  name="T_32PCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0010),  weird=False), # 32 bit pointer to 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0510),  name="T_32PFCHAR",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0010),  weird=True ), # 16:32 pointer to 8 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0610),  name="T_64PCHAR",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0010),  weird=True ), # 64 bit pointer to 8 bit signed

    CvInfoType(key=CvdumpTypeKey(0x0020),  name="T_UCHAR",        fmt="B",    size=1,   pointer=None,                   weird=False), # 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0120),  name="T_PUCHAR",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0020),  weird=True ), # 16 bit pointer to 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0220),  name="T_PFUCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0020),  weird=True ), # 16:16 far pointer to 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0320),  name="T_PHUCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0020),  weird=True ), # 16:16 huge pointer to 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0420),  name="T_32PUCHAR",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0020),  weird=False), # 32 bit pointer to 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0520),  name="T_32PFUCHAR",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0020),  weird=True ), # 16:32 pointer to 8 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0620),  name="T_64PUCHAR",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0020),  weird=True ), # 64 bit pointer to 8 bit unsigned


#      really a character types

    CvInfoType(key=CvdumpTypeKey(0x0070),  name="T_RCHAR",        fmt="c",    size=1,   pointer=None,                   weird=False), # really a char
    CvInfoType(key=CvdumpTypeKey(0x0170),  name="T_PRCHAR",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0070),  weird=True ), # 16 bit pointer to a real char
    CvInfoType(key=CvdumpTypeKey(0x0270),  name="T_PFRCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0070),  weird=True ), # 16:16 far pointer to a real char
    CvInfoType(key=CvdumpTypeKey(0x0370),  name="T_PHRCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0070),  weird=True ), # 16:16 huge pointer to a real char
    CvInfoType(key=CvdumpTypeKey(0x0470),  name="T_32PRCHAR",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0070),  weird=False), # 32 bit pointer to a real char
    CvInfoType(key=CvdumpTypeKey(0x0570),  name="T_32PFRCHAR",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0070),  weird=True ), # 16:32 pointer to a real char
    CvInfoType(key=CvdumpTypeKey(0x0670),  name="T_64PRCHAR",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0070),  weird=True ), # 64 bit pointer to a real char


#      really a wide character types

    CvInfoType(key=CvdumpTypeKey(0x0071),  name="T_WCHAR",        fmt="H",    size=2,   pointer=None,                   weird=False), # wide char
    CvInfoType(key=CvdumpTypeKey(0x0171),  name="T_PWCHAR",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0071),  weird=True ), # 16 bit pointer to a wide char
    CvInfoType(key=CvdumpTypeKey(0x0271),  name="T_PFWCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0071),  weird=True ), # 16:16 far pointer to a wide char
    CvInfoType(key=CvdumpTypeKey(0x0371),  name="T_PHWCHAR",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0071),  weird=True ), # 16:16 huge pointer to a wide char
    CvInfoType(key=CvdumpTypeKey(0x0471),  name="T_32PWCHAR",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0071),  weird=False), # 32 bit pointer to a wide char
    CvInfoType(key=CvdumpTypeKey(0x0571),  name="T_32PFWCHAR",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0071),  weird=True ), # 16:32 pointer to a wide char
    CvInfoType(key=CvdumpTypeKey(0x0671),  name="T_64PWCHAR",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0071),  weird=True ), # 64 bit pointer to a wide char

#      really a 16-bit unicode char

    CvInfoType(key=CvdumpTypeKey(0x007a),  name="T_CHAR16",       fmt="H",    size=2,   pointer=None,                   weird=True ), # 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x017a),  name="T_PCHAR16",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x007a),  weird=True ), # 16 bit pointer to a 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x027a),  name="T_PFCHAR16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007a),  weird=True ), # 16:16 far pointer to a 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x037a),  name="T_PHCHAR16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007a),  weird=True ), # 16:16 huge pointer to a 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x047a),  name="T_32PCHAR16",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007a),  weird=True ), # 32 bit pointer to a 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x057a),  name="T_32PFCHAR16",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x007a),  weird=True ), # 16:32 pointer to a 16-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x067a),  name="T_64PCHAR16",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x007a),  weird=True ), # 64 bit pointer to a 16-bit unicode char

#      really a 32-bit unicode char

    CvInfoType(key=CvdumpTypeKey(0x007b),  name="T_CHAR32",       fmt="I",    size=4,   pointer=None,                   weird=True ), # 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x017b),  name="T_PCHAR32",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x007b),  weird=True ), # 16 bit pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x027b),  name="T_PFCHAR32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007b),  weird=True ), # 16:16 far pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x037b),  name="T_PHCHAR32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007b),  weird=True ), # 16:16 huge pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x047b),  name="T_32PCHAR32",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x007b),  weird=True ), # 32 bit pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x057b),  name="T_32PFCHAR32",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x007b),  weird=True ), # 16:32 pointer to a 32-bit unicode char
    CvInfoType(key=CvdumpTypeKey(0x067b),  name="T_64PCHAR32",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x007b),  weird=True ), # 64 bit pointer to a 32-bit unicode char

#      8 bit int types

    CvInfoType(key=CvdumpTypeKey(0x0068),  name="T_INT1",         fmt="b",    size=1,   pointer=None,                   weird=True ), # 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0168),  name="T_PINT1",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0068),  weird=True ), # 16 bit pointer to 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0268),  name="T_PFINT1",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0068),  weird=True ), # 16:16 far pointer to 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0368),  name="T_PHINT1",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0068),  weird=True ), # 16:16 huge pointer to 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0468),  name="T_32PINT1",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0068),  weird=True ), # 32 bit pointer to 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0568),  name="T_32PFINT1",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0068),  weird=True ), # 16:32 pointer to 8 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0668),  name="T_64PINT1",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0068),  weird=True ), # 64 bit pointer to 8 bit signed int

    CvInfoType(key=CvdumpTypeKey(0x0069),  name="T_UINT1",        fmt="B",    size=1,   pointer=None,                   weird=True ), # 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0169),  name="T_PUINT1",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0069),  weird=True ), # 16 bit pointer to 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0269),  name="T_PFUINT1",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0069),  weird=True ), # 16:16 far pointer to 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0369),  name="T_PHUINT1",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0069),  weird=True ), # 16:16 huge pointer to 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0469),  name="T_32PUINT1",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0069),  weird=True ), # 32 bit pointer to 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0569),  name="T_32PFUINT1",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0069),  weird=True ), # 16:32 pointer to 8 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0669),  name="T_64PUINT1",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0069),  weird=True ), # 64 bit pointer to 8 bit unsigned int


#      16 bit short types

    CvInfoType(key=CvdumpTypeKey(0x0011),  name="T_SHORT",        fmt="h",    size=2,   pointer=None,                   weird=False), # 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0111),  name="T_PSHORT",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0011),  weird=True ), # 16 bit pointer to 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0211),  name="T_PFSHORT",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0011),  weird=True ), # 16:16 far pointer to 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0311),  name="T_PHSHORT",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0011),  weird=True ), # 16:16 huge pointer to 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0411),  name="T_32PSHORT",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0011),  weird=False), # 32 bit pointer to 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0511),  name="T_32PFSHORT",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0011),  weird=True ), # 16:32 pointer to 16 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0611),  name="T_64PSHORT",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0011),  weird=True ), # 64 bit pointer to 16 bit signed

    CvInfoType(key=CvdumpTypeKey(0x0021),  name="T_USHORT",       fmt="H",    size=2,   pointer=None,                   weird=False), # 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0121),  name="T_PUSHORT",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0021),  weird=True ), # 16 bit pointer to 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0221),  name="T_PFUSHORT",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0021),  weird=True ), # 16:16 far pointer to 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0321),  name="T_PHUSHORT",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0021),  weird=True ), # 16:16 huge pointer to 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0421),  name="T_32PUSHORT",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0021),  weird=False), # 32 bit pointer to 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0521),  name="T_32PFUSHORT",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0021),  weird=True ), # 16:32 pointer to 16 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0621),  name="T_64PUSHORT",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0021),  weird=True ), # 64 bit pointer to 16 bit unsigned


#      16 bit int types

    CvInfoType(key=CvdumpTypeKey(0x0072),  name="T_INT2",         fmt="h",    size=2,   pointer=None,                   weird=True ), # 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0172),  name="T_PINT2",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0072),  weird=True ), # 16 bit pointer to 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0272),  name="T_PFINT2",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0072),  weird=True ), # 16:16 far pointer to 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0372),  name="T_PHINT2",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0072),  weird=True ), # 16:16 huge pointer to 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0472),  name="T_32PINT2",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0072),  weird=True ), # 32 bit pointer to 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0572),  name="T_32PFINT2",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0072),  weird=True ), # 16:32 pointer to 16 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0672),  name="T_64PINT2",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0072),  weird=True ), # 64 bit pointer to 16 bit signed int

    CvInfoType(key=CvdumpTypeKey(0x0073),  name="T_UINT2",        fmt="H",    size=2,   pointer=None,                   weird=True ), # 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0173),  name="T_PUINT2",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0073),  weird=True ), # 16 bit pointer to 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0273),  name="T_PFUINT2",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0073),  weird=True ), # 16:16 far pointer to 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0373),  name="T_PHUINT2",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0073),  weird=True ), # 16:16 huge pointer to 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0473),  name="T_32PUINT2",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0073),  weird=True ), # 32 bit pointer to 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0573),  name="T_32PFUINT2",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0073),  weird=True ), # 16:32 pointer to 16 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0673),  name="T_64PUINT2",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0073),  weird=True ), # 64 bit pointer to 16 bit unsigned int


#      32 bit long types

    CvInfoType(key=CvdumpTypeKey(0x0012),  name="T_LONG",         fmt="l",    size=4,   pointer=None,                   weird=False), # 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0112),  name="T_PLONG",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0112),  weird=True ), # 16 bit pointer to 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0212),  name="T_PFLONG",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0112),  weird=True ), # 16:16 far pointer to 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0312),  name="T_PHLONG",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0112),  weird=True ), # 16:16 huge pointer to 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0412),  name="T_32PLONG",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0112),  weird=False), # 32 bit pointer to 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0512),  name="T_32PFLONG",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0112),  weird=True ), # 16:32 pointer to 32 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0612),  name="T_64PLONG",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0112),  weird=True ), # 64 bit pointer to 32 bit signed

    CvInfoType(key=CvdumpTypeKey(0x0022),  name="T_ULONG",        fmt="L",    size=4,   pointer=None,                   weird=False), # 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0122),  name="T_PULONG",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0022),  weird=True ), # 16 bit pointer to 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0222),  name="T_PFULONG",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0022),  weird=True ), # 16:16 far pointer to 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0322),  name="T_PHULONG",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0022),  weird=True ), # 16:16 huge pointer to 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0422),  name="T_32PULONG",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0022),  weird=False), # 32 bit pointer to 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0522),  name="T_32PFULONG",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0022),  weird=True ), # 16:32 pointer to 32 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0622),  name="T_64PULONG",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0022),  weird=True ), # 64 bit pointer to 32 bit unsigned

#      32 bit int types

    CvInfoType(key=CvdumpTypeKey(0x0074),  name="T_INT4",         fmt="i",    size=4,   pointer=None,                   weird=False), # 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0174),  name="T_PINT4",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0074),  weird=True ), # 16 bit pointer to 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0274),  name="T_PFINT4",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0074),  weird=True ), # 16:16 far pointer to 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0374),  name="T_PHINT4",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0074),  weird=True ), # 16:16 huge pointer to 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0474),  name="T_32PINT4",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0074),  weird=False), # 32 bit pointer to 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0574),  name="T_32PFINT4",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0074),  weird=True ), # 16:32 pointer to 32 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0674),  name="T_64PINT4",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0074),  weird=True ), # 64 bit pointer to 32 bit signed int

    CvInfoType(key=CvdumpTypeKey(0x0075),  name="T_UINT4",        fmt="I",    size=4,   pointer=None,                   weird=False), # 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0175),  name="T_PUINT4",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0075),  weird=True ), # 16 bit pointer to 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0275),  name="T_PFUINT4",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0075),  weird=True ), # 16:16 far pointer to 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0375),  name="T_PHUINT4",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0075),  weird=True ), # 16:16 huge pointer to 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0475),  name="T_32PUINT4",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0075),  weird=False), # 32 bit pointer to 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0575),  name="T_32PFUINT4",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0075),  weird=True ), # 16:32 pointer to 32 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0675),  name="T_64PUINT4",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0075),  weird=True ), # 64 bit pointer to 32 bit unsigned int


#      64 bit quad types

    CvInfoType(key=CvdumpTypeKey(0x0013),  name="T_QUAD",         fmt="q",    size=8,   pointer=None,                   weird=False), # 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0113),  name="T_PQUAD",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0013),  weird=True ), # 16 bit pointer to 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0213),  name="T_PFQUAD",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0013),  weird=True ), # 16:16 far pointer to 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0313),  name="T_PHQUAD",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0013),  weird=True ), # 16:16 huge pointer to 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0413),  name="T_32PQUAD",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0013),  weird=False), # 32 bit pointer to 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0513),  name="T_32PFQUAD",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0013),  weird=True ), # 16:32 pointer to 64 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0613),  name="T_64PQUAD",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0013),  weird=True ), # 64 bit pointer to 64 bit signed

    CvInfoType(key=CvdumpTypeKey(0x0023),  name="T_UQUAD",        fmt="Q",    size=8,   pointer=None,                   weird=False), # 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0123),  name="T_PUQUAD",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0023),  weird=True ), # 16 bit pointer to 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0223),  name="T_PFUQUAD",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0023),  weird=True ), # 16:16 far pointer to 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0323),  name="T_PHUQUAD",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0023),  weird=True ), # 16:16 huge pointer to 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0423),  name="T_32PUQUAD",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0023),  weird=False), # 32 bit pointer to 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0523),  name="T_32PFUQUAD",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0023),  weird=True ), # 16:32 pointer to 64 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0623),  name="T_64PUQUAD",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0023),  weird=True ), # 64 bit pointer to 64 bit unsigned


#      64 bit int types

    CvInfoType(key=CvdumpTypeKey(0x0076),  name="T_INT8",         fmt="q",    size=8,   pointer=None,                   weird=True ), # 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0176),  name="T_PINT8",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0076),  weird=True ), # 16 bit pointer to 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0276),  name="T_PFINT8",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0076),  weird=True ), # 16:16 far pointer to 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0376),  name="T_PHINT8",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0076),  weird=True ), # 16:16 huge pointer to 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0476),  name="T_32PINT8",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0076),  weird=True ), # 32 bit pointer to 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0576),  name="T_32PFINT8",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0076),  weird=True ), # 16:32 pointer to 64 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0676),  name="T_64PINT8",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0076),  weird=True ), # 64 bit pointer to 64 bit signed int

    CvInfoType(key=CvdumpTypeKey(0x0077),  name="T_UINT8",        fmt="Q",    size=8,   pointer=None,                   weird=True ), # 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0177),  name="T_PUINT8",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0077),  weird=True ), # 16 bit pointer to 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0277),  name="T_PFUINT8",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0077),  weird=True ), # 16:16 far pointer to 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0377),  name="T_PHUINT8",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0077),  weird=True ), # 16:16 huge pointer to 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0477),  name="T_32PUINT8",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0077),  weird=True ), # 32 bit pointer to 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0577),  name="T_32PFUINT8",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0077),  weird=True ), # 16:32 pointer to 64 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0677),  name="T_64PUINT8",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0077),  weird=True ), # 64 bit pointer to 64 bit unsigned int


#      128 bit octet types

    CvInfoType(key=CvdumpTypeKey(0x0014),  name="T_OCT",          fmt="16B",  size=16,  pointer=None,                   weird=True ), # 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0114),  name="T_POCT",         fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0014),  weird=True ), # 16 bit pointer to 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0214),  name="T_PFOCT",        fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0014),  weird=True ), # 16:16 far pointer to 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0314),  name="T_PHOCT",        fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0014),  weird=True ), # 16:16 huge pointer to 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0414),  name="T_32POCT",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0014),  weird=True ), # 32 bit pointer to 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0514),  name="T_32PFOCT",      fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0014),  weird=True ), # 16:32 pointer to 128 bit signed
    CvInfoType(key=CvdumpTypeKey(0x0614),  name="T_64POCT",       fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0014),  weird=True ), # 64 bit pointer to 128 bit signed

    CvInfoType(key=CvdumpTypeKey(0x0024),  name="T_UOCT",         fmt="16B",  size=16,  pointer=None,                   weird=True ), # 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0124),  name="T_PUOCT",        fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0024),  weird=True ), # 16 bit pointer to 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0224),  name="T_PFUOCT",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0024),  weird=True ), # 16:16 far pointer to 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0324),  name="T_PHUOCT",       fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0024),  weird=True ), # 16:16 huge pointer to 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0424),  name="T_32PUOCT",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0024),  weird=True ), # 32 bit pointer to 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0524),  name="T_32PFUOCT",     fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0024),  weird=True ), # 16:32 pointer to 128 bit unsigned
    CvInfoType(key=CvdumpTypeKey(0x0624),  name="T_64PUOCT",      fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0024),  weird=True ), # 64 bit pointer to 128 bit unsigned


#      128 bit int types

    CvInfoType(key=CvdumpTypeKey(0x0078),  name="T_INT16",        fmt="16B",  size=16,  pointer=None,                   weird=True ), # 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0178),  name="T_PINT16",       fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0078),  weird=True ), # 16 bit pointer to 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0278),  name="T_PFINT16",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0078),  weird=True ), # 16:16 far pointer to 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0378),  name="T_PHINT16",      fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0078),  weird=True ), # 16:16 huge pointer to 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0478),  name="T_32PINT16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0078),  weird=True ), # 32 bit pointer to 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0578),  name="T_32PFINT16",    fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0078),  weird=True ), # 16:32 pointer to 128 bit signed int
    CvInfoType(key=CvdumpTypeKey(0x0678),  name="T_64PINT16",     fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0078),  weird=True ), # 64 bit pointer to 128 bit signed int

    CvInfoType(key=CvdumpTypeKey(0x0079),  name="T_UINT16",       fmt="16B",  size=16,  pointer= None,   weird=True ), # 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0179),  name="T_PUINT16",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0079),  weird=True ), # 16 bit pointer to 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0279),  name="T_PFUINT16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0079),  weird=True ), # 16:16 far pointer to 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0379),  name="T_PHUINT16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0079),  weird=True ), # 16:16 huge pointer to 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0479),  name="T_32PUINT16",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0079),  weird=True ), # 32 bit pointer to 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0579),  name="T_32PFUINT16",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0079),  weird=True ), # 16:32 pointer to 128 bit unsigned int
    CvInfoType(key=CvdumpTypeKey(0x0679),  name="T_64PUINT16",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0079),  weird=True ), # 64 bit pointer to 128 bit unsigned int


#      16 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0046),  name="T_REAL16",       fmt="2B",   size=2,   pointer=None,                   weird=True ), # 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0146),  name="T_PREAL16",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0046),  weird=True ), # 16 bit pointer to 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0246),  name="T_PFREAL16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0046),  weird=True ), # 16:16 far pointer to 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0346),  name="T_PHREAL16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0046),  weird=True ), # 16:16 huge pointer to 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0446),  name="T_32PREAL16",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0046),  weird=True ), # 32 bit pointer to 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0546),  name="T_32PFREAL16",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0046),  weird=True ), # 16:32 pointer to 16 bit real
    CvInfoType(key=CvdumpTypeKey(0x0646),  name="T_64PREAL16",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0046),  weird=True ), # 64 bit pointer to 16 bit real


#      32 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0040),  name="T_REAL32",       fmt="f",    size=4,   pointer=None,                   weird=False), # 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0140),  name="T_PREAL32",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0040),  weird=True ), # 16 bit pointer to 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0240),  name="T_PFREAL32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0040),  weird=True ), # 16:16 far pointer to 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0340),  name="T_PHREAL32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0040),  weird=True ), # 16:16 huge pointer to 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0440),  name="T_32PREAL32",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0040),  weird=False), # 32 bit pointer to 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0540),  name="T_32PFREAL32",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0040),  weird=True ), # 16:32 pointer to 32 bit real
    CvInfoType(key=CvdumpTypeKey(0x0640),  name="T_64PREAL32",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0040),  weird=True ), # 64 bit pointer to 32 bit real


#      32 bit partial-precision real types

    CvInfoType(key=CvdumpTypeKey(0x0045),  name="T_REAL32PP",     fmt="4B",   size=4,   pointer=None,                   weird=True ), # 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0145),  name="T_PREAL32PP",    fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0045),  weird=True ), # 16 bit pointer to 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0245),  name="T_PFREAL32PP",   fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0045),  weird=True ), # 16:16 far pointer to 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0345),  name="T_PHREAL32PP",   fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0045),  weird=True ), # 16:16 huge pointer to 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0445),  name="T_32PREAL32PP",  fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0045),  weird=True ), # 32 bit pointer to 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0545),  name="T_32PFREAL32PP", fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0045),  weird=True ), # 16:32 pointer to 32 bit PP real
    CvInfoType(key=CvdumpTypeKey(0x0645),  name="T_64PREAL32PP",  fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0045),  weird=True ), # 64 bit pointer to 32 bit PP real


#      48 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0044),  name="T_REAL48",       fmt="6B",   size=6,   pointer=None,                   weird=True ), # 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0144),  name="T_PREAL48",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0044),  weird=True ), # 16 bit pointer to 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0244),  name="T_PFREAL48",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0044),  weird=True ), # 16:16 far pointer to 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0344),  name="T_PHREAL48",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0044),  weird=True ), # 16:16 huge pointer to 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0444),  name="T_32PREAL48",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0044),  weird=True ), # 32 bit pointer to 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0544),  name="T_32PFREAL48",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0044),  weird=True ), # 16:32 pointer to 48 bit real
    CvInfoType(key=CvdumpTypeKey(0x0644),  name="T_64PREAL48",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0044),  weird=True ), # 64 bit pointer to 48 bit real


#      64 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0041),  name="T_REAL64",       fmt="d",    size=8,   pointer=None,                   weird=False), # 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0141),  name="T_PREAL64",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0041),  weird=True ), # 16 bit pointer to 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0241),  name="T_PFREAL64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0041),  weird=True ), # 16:16 far pointer to 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0341),  name="T_PHREAL64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0041),  weird=True ), # 16:16 huge pointer to 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0441),  name="T_32PREAL64",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0041),  weird=False), # 32 bit pointer to 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0541),  name="T_32PFREAL64",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0041),  weird=True ), # 16:32 pointer to 64 bit real
    CvInfoType(key=CvdumpTypeKey(0x0641),  name="T_64PREAL64",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0041),  weird=True ), # 64 bit pointer to 64 bit real


#      80 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0042),  name="T_REAL80",       fmt="10B",  size=10,  pointer=None,                   weird=True ), # 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0142),  name="T_PREAL80",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0042),  weird=True ), # 16 bit pointer to 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0242),  name="T_PFREAL80",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0042),  weird=True ), # 16:16 far pointer to 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0342),  name="T_PHREAL80",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0042),  weird=True ), # 16:16 huge pointer to 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0442),  name="T_32PREAL80",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0042),  weird=True ), # 32 bit pointer to 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0542),  name="T_32PFREAL80",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0042),  weird=True ), # 16:32 pointer to 80 bit real
    CvInfoType(key=CvdumpTypeKey(0x0642),  name="T_64PREAL80",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0042),  weird=True ), # 64 bit pointer to 80 bit real


#      128 bit real types

    CvInfoType(key=CvdumpTypeKey(0x0043),  name="T_REAL128",      fmt="16B",  size=16,  pointer=None,                   weird=True ), # 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0143),  name="T_PREAL128",     fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0043),  weird=True ), # 16 bit pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0243),  name="T_PFREAL128",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0043),  weird=True ), # 16:16 far pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0343),  name="T_PHREAL128",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0043),  weird=True ), # 16:16 huge pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0443),  name="T_32PREAL128",   fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0043),  weird=True ), # 32 bit pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0543),  name="T_32PFREAL128",  fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0043),  weird=True ), # 16:32 pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0643),  name="T_64PREAL128",   fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0043),  weird=True ), # 64 bit pointer to 128 bit real


#      32 bit complex types

    CvInfoType(key=CvdumpTypeKey(0x0050),  name="T_CPLX32",       fmt="4B",   size=4,   pointer=None,                   weird=True ), # 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0150),  name="T_PCPLX32",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0050),  weird=True ), # 16 bit pointer to 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0250),  name="T_PFCPLX32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0050),  weird=True ), # 16:16 far pointer to 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0350),  name="T_PHCPLX32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0050),  weird=True ), # 16:16 huge pointer to 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0450),  name="T_32PCPLX32",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0050),  weird=True ), # 32 bit pointer to 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0550),  name="T_32PFCPLX32",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0050),  weird=True ), # 16:32 pointer to 32 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0650),  name="T_64PCPLX32",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0050),  weird=True ), # 64 bit pointer to 32 bit complex


#      64 bit complex types

    CvInfoType(key=CvdumpTypeKey(0x0051),  name="T_CPLX64",       fmt="F",    size=8,   pointer=None,                   weird=True ), # 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0151),  name="T_PCPLX64",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0051),  weird=True ), # 16 bit pointer to 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0251),  name="T_PFCPLX64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0051),  weird=True ), # 16:16 far pointer to 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0351),  name="T_PHCPLX64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0051),  weird=True ), # 16:16 huge pointer to 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0451),  name="T_32PCPLX64",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0051),  weird=True ), # 32 bit pointer to 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0551),  name="T_32PFCPLX64",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0051),  weird=True ), # 16:32 pointer to 64 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0651),  name="T_64PCPLX64",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0051),  weird=True ), # 64 bit pointer to 64 bit complex


#      80 bit complex types

    CvInfoType(key=CvdumpTypeKey(0x0052),  name="T_CPLX80",       fmt="10B",  size=10,  pointer=None,                   weird=True ), # 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0152),  name="T_PCPLX80",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0052),  weird=True ), # 16 bit pointer to 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0252),  name="T_PFCPLX80",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0052),  weird=True ), # 16:16 far pointer to 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0352),  name="T_PHCPLX80",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0052),  weird=True ), # 16:16 huge pointer to 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0452),  name="T_32PCPLX80",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0052),  weird=True ), # 32 bit pointer to 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0552),  name="T_32PFCPLX80",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0052),  weird=True ), # 16:32 pointer to 80 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0652),  name="T_64PCPLX80",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0052),  weird=True ), # 64 bit pointer to 80 bit complex


#      128 bit complex types

    CvInfoType(key=CvdumpTypeKey(0x0053),  name="T_CPLX128",      fmt="D",    size=16,  pointer=None,                   weird=True ), # 128 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0153),  name="T_PCPLX128",     fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0053),  weird=True ), # 16 bit pointer to 128 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0253),  name="T_PFCPLX128",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0053),  weird=True ), # 16:16 far pointer to 128 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0353),  name="T_PHCPLX128",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0053),  weird=True ), # 16:16 huge pointer to 128 bit real
    CvInfoType(key=CvdumpTypeKey(0x0453),  name="T_32PCPLX128",   fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0053),  weird=True ), # 32 bit pointer to 128 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0553),  name="T_32PFCPLX128",  fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0053),  weird=True ), # 16:32 pointer to 128 bit complex
    CvInfoType(key=CvdumpTypeKey(0x0653),  name="T_64PCPLX128",   fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0053),  weird=True ), # 64 bit pointer to 128 bit complex


#      boolean types

    CvInfoType(key=CvdumpTypeKey(0x0030),  name="T_BOOL08",       fmt="B",    size=1,   pointer=None,                   weird=True ), # 8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0130),  name="T_PBOOL08",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0030),  weird=True ), # 16 bit pointer to  8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0230),  name="T_PFBOOL08",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0030),  weird=True ), # 16:16 far pointer to  8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0330),  name="T_PHBOOL08",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0030),  weird=True ), # 16:16 huge pointer to  8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0430),  name="T_32PBOOL08",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0030),  weird=True ), # 32 bit pointer to 8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0530),  name="T_32PFBOOL08",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0030),  weird=True ), # 16:32 pointer to 8 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0630),  name="T_64PBOOL08",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0030),  weird=True ), # 64 bit pointer to 8 bit boolean

    CvInfoType(key=CvdumpTypeKey(0x0031),  name="T_BOOL16",       fmt="H",    size=2,   pointer=None,                   weird=True ), # 16 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0131),  name="T_PBOOL16",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0031),  weird=True ), # 16 bit pointer to 16 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0231),  name="T_PFBOOL16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0031),  weird=True ), # 16:16 far pointer to 16 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0331),  name="T_PHBOOL16",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0031),  weird=True ), # 16:16 huge pointer to 16 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0431),  name="T_32PBOOL16",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0031),  weird=True ), # 32 bit pointer to 18 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0531),  name="T_32PFBOOL16",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0031),  weird=True ), # 16:32 pointer to 16 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0631),  name="T_64PBOOL16",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0031),  weird=True ), # 64 bit pointer to 18 bit boolean

    CvInfoType(key=CvdumpTypeKey(0x0032),  name="T_BOOL32",       fmt="I",    size=4,   pointer=None,                   weird=True ), # 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0132),  name="T_PBOOL32",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0032),  weird=True ), # 16 bit pointer to 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0232),  name="T_PFBOOL32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0032),  weird=True ), # 16:16 far pointer to 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0332),  name="T_PHBOOL32",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0032),  weird=True ), # 16:16 huge pointer to 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0432),  name="T_32PBOOL32",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0032),  weird=True ), # 32 bit pointer to 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0532),  name="T_32PFBOOL32",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0032),  weird=True ), # 16:32 pointer to 32 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0632),  name="T_64PBOOL32",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0032),  weird=True ), # 64 bit pointer to 32 bit boolean

    CvInfoType(key=CvdumpTypeKey(0x0033),  name="T_BOOL64",       fmt="Q",    size=8,   pointer=None,                   weird=True ), # 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0133),  name="T_PBOOL64",      fmt="H",    size=2,   pointer=CvdumpTypeKey(0x0033),  weird=True ), # 16 bit pointer to 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0233),  name="T_PFBOOL64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0033),  weird=True ), # 16:16 far pointer to 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0333),  name="T_PHBOOL64",     fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0033),  weird=True ), # 16:16 huge pointer to 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0433),  name="T_32PBOOL64",    fmt="I",    size=4,   pointer=CvdumpTypeKey(0x0033),  weird=True ), # 32 bit pointer to 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0533),  name="T_32PFBOOL64",   fmt="6x",   size=6,   pointer=CvdumpTypeKey(0x0033),  weird=True ), # 16:32 pointer to 64 bit boolean
    CvInfoType(key=CvdumpTypeKey(0x0633),  name="T_64PBOOL64",    fmt="Q",    size=8,   pointer=CvdumpTypeKey(0x0033),  weird=True ), # 64 bit pointer to 64 bit boolean


#      ???

    CvInfoType(key=CvdumpTypeKey(0x01f0),  name="T_NCVPTR",       fmt="",     size=0,   pointer=None,                   weird=True ), # CV Internal type for created near pointers
    CvInfoType(key=CvdumpTypeKey(0x02f0),  name="T_FCVPTR",       fmt="",     size=0,   pointer=None,                   weird=True ), # CV Internal type for created far pointers
    CvInfoType(key=CvdumpTypeKey(0x03f0),  name="T_HCVPTR",       fmt="",     size=0,   pointer=None,                   weird=True ), # CV Internal type for created huge pointers
    CvInfoType(key=CvdumpTypeKey(0x04f0),  name="T_32NCVPTR",     fmt="",     size=0,   pointer=None,                   weird=True ), # CV Internal type for created near 32-bit pointers
    CvInfoType(key=CvdumpTypeKey(0x05f0),  name="T_32FCVPTR",     fmt="",     size=0,   pointer=None,                   weird=True ), # CV Internal type for created far 32-bit pointers
    CvInfoType(key=CvdumpTypeKey(0x06f0),  name="T_64NCVPTR",     fmt="",     size=0,   pointer=None,                   weird=True ), # CV Internal type for created near 64-bit pointers
)
# fmt: on


_CVInfoTypeEnum = new_class("_CVInfoTypeEnum", bases=(CvdumpTypeKey, Enum))
CVInfoTypeEnum = _CVInfoTypeEnum(
    "CVInfoTypeEnum", {cv.name: cv.key for cv in _CVINFO_TYPES}
)


_TYPE_ENUM_E = MappingProxyType({cv.key: cv for cv in _CVINFO_TYPES})


# Just add the key at the front to get a CvInfoType tuple.
_UNKNOWN_TYPE_ATTRS = ("???", "", 0, None, True)


def cvinfo_type_name(key: CvdumpTypeKey) -> str:
    return _TYPE_ENUM_E.get(key, CvInfoType(key, *_UNKNOWN_TYPE_ATTRS)).name


def get_cvinfo(key: CvdumpTypeKey) -> CvInfoType:
    return _TYPE_ENUM_E[key]


def scalar_type_pointer(key: CvdumpTypeKey) -> bool:
    return get_cvinfo(key).pointer is not None


def scalar_type_size(key: CvdumpTypeKey) -> int:
    return get_cvinfo(key).size


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
