"""Type enum modified from cvinfo.h released under MIT license.
https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h
See `LICENSE.cvdump.txt` for details.
"""

from typing import NamedTuple


class CvInfoType(NamedTuple):
    key: int
    """The integer type key."""
    name: str
    """The name of this type as given in cvinfo.h."""
    fmt: str
    """The struct.unpack format char(s) for this type."""
    size: int
    """The type's footprint in bytes."""
    special: bool
    """If true, there is more processing required to manage this type."""
    pointer: int | None
    """If set, this type is a pointer to another CVinfo type."""
    weird: bool
    """If we encounter this type, log a message about it for potential debugging."""


# fmt: off
_TYPE_ENUM_E = {

#      Special Types

    0x0000: CvInfoType(0x0000,  "T_NOTYPE",       "",     0,   True,   None,    False), # uncharacterized type (no type)
    0x0001: CvInfoType(0x0001,  "T_ABS",          "",     0,   True,   None,    True ), # absolute symbol
    0x0002: CvInfoType(0x0002,  "T_SEGMENT",      "",     0,   True,   None,    True ), # segment type
    0x0003: CvInfoType(0x0003,  "T_VOID",         "",     0,   False,  None,    False), # void
    0x0008: CvInfoType(0x0008,  "T_HRESULT",      "I",    4,   False,  None,    False), # OLE/COM HRESULT
    0x0408: CvInfoType(0x0408,  "T_32PHRESULT",   "I",    4,   False,  0x0008,  False), # OLE/COM HRESULT __ptr32 *
    0x0608: CvInfoType(0x0608,  "T_64PHRESULT",   "Q",    8,   False,  0x0008,  True ), # OLE/COM HRESULT __ptr64 *

    0x0103: CvInfoType(0x0103,  "T_PVOID",        "H",    2,   False,  0x0003,  True ), # near pointer to void
    0x0203: CvInfoType(0x0203,  "T_PFVOID",       "I",    4,   False,  0x0003,  True ), # far pointer to void
    0x0303: CvInfoType(0x0303,  "T_PHVOID",       "I",    4,   False,  0x0003,  True ), # huge pointer to void
    0x0403: CvInfoType(0x0403,  "T_32PVOID",      "I",    4,   False,  0x0003,  False), # 32 bit pointer to void
    0x0503: CvInfoType(0x0503,  "T_32PFVOID",     "6x",   6,   False,  0x0003,  True ), # 16:32 pointer to void
    0x0603: CvInfoType(0x0603,  "T_64PVOID",      "Q",    8,   False,  0x0003,  True ), # 64 bit pointer to void
    0x0004: CvInfoType(0x0004,  "T_CURRENCY",     "",     0,   True,   None,    True ), # BASIC 8 byte currency value
    0x0005: CvInfoType(0x0005,  "T_NBASICSTR",    "",     0,   True,   None,    True ), # Near BASIC string
    0x0006: CvInfoType(0x0006,  "T_FBASICSTR",    "",     0,   True,   None,    True ), # Far BASIC string
    0x0007: CvInfoType(0x0007,  "T_NOTTRANS",     "",     0,   True,   None,    True ), # type not translated by cvpack
    0x0060: CvInfoType(0x0060,  "T_BIT",          "",     0,   True,   None,    True ), # bit
    0x0061: CvInfoType(0x0061,  "T_PASCHAR",      "",     0,   True,   None,    True ), # Pascal CHAR
    0x0062: CvInfoType(0x0062,  "T_BOOL32FF",     "i",    4,   False,  None,    True ), # 32-bit BOOL where true is 0xffffffff


#      Character types

    0x0010: CvInfoType(0x0010,  "T_CHAR",         "b",    1,   False,  None,    False), # 8 bit signed
    0x0110: CvInfoType(0x0110,  "T_PCHAR",        "H",    2,   False,  0x0010,  True ), # 16 bit pointer to 8 bit signed
    0x0210: CvInfoType(0x0210,  "T_PFCHAR",       "I",    4,   False,  0x0010,  True ), # 16:16 far pointer to 8 bit signed
    0x0310: CvInfoType(0x0310,  "T_PHCHAR",       "I",    4,   False,  0x0010,  True ), # 16:16 huge pointer to 8 bit signed
    0x0410: CvInfoType(0x0410,  "T_32PCHAR",      "I",    4,   False,  0x0010,  False), # 32 bit pointer to 8 bit signed
    0x0510: CvInfoType(0x0510,  "T_32PFCHAR",     "6x",   6,   False,  0x0010,  True ), # 16:32 pointer to 8 bit signed
    0x0610: CvInfoType(0x0610,  "T_64PCHAR",      "Q",    8,   False,  0x0010,  True ), # 64 bit pointer to 8 bit signed

    0x0020: CvInfoType(0x0020,  "T_UCHAR",        "B",    1,   False,  None,    False), # 8 bit unsigned
    0x0120: CvInfoType(0x0120,  "T_PUCHAR",       "H",    2,   False,  0x0020,  True ), # 16 bit pointer to 8 bit unsigned
    0x0220: CvInfoType(0x0220,  "T_PFUCHAR",      "I",    4,   False,  0x0020,  True ), # 16:16 far pointer to 8 bit unsigned
    0x0320: CvInfoType(0x0320,  "T_PHUCHAR",      "I",    4,   False,  0x0020,  True ), # 16:16 huge pointer to 8 bit unsigned
    0x0420: CvInfoType(0x0420,  "T_32PUCHAR",     "I",    4,   False,  0x0020,  False), # 32 bit pointer to 8 bit unsigned
    0x0520: CvInfoType(0x0520,  "T_32PFUCHAR",    "6x",   6,   False,  0x0020,  True ), # 16:32 pointer to 8 bit unsigned
    0x0620: CvInfoType(0x0620,  "T_64PUCHAR",     "Q",    8,   False,  0x0020,  True ), # 64 bit pointer to 8 bit unsigned


#      really a character types

    0x0070: CvInfoType(0x0070,  "T_RCHAR",        "c",    1,   False,  None,    False), # really a char
    0x0170: CvInfoType(0x0170,  "T_PRCHAR",       "H",    2,   False,  0x0070,  True ), # 16 bit pointer to a real char
    0x0270: CvInfoType(0x0270,  "T_PFRCHAR",      "I",    4,   False,  0x0070,  True ), # 16:16 far pointer to a real char
    0x0370: CvInfoType(0x0370,  "T_PHRCHAR",      "I",    4,   False,  0x0070,  True ), # 16:16 huge pointer to a real char
    0x0470: CvInfoType(0x0470,  "T_32PRCHAR",     "I",    4,   False,  0x0070,  False), # 32 bit pointer to a real char
    0x0570: CvInfoType(0x0570,  "T_32PFRCHAR",    "6x",   6,   False,  0x0070,  True ), # 16:32 pointer to a real char
    0x0670: CvInfoType(0x0670,  "T_64PRCHAR",     "Q",    8,   False,  0x0070,  True ), # 64 bit pointer to a real char


#      really a wide character types

    0x0071: CvInfoType(0x0071,  "T_WCHAR",        "H",    2,   False,  None,    False), # wide char
    0x0171: CvInfoType(0x0171,  "T_PWCHAR",       "H",    2,   False,  0x0071,  True ), # 16 bit pointer to a wide char
    0x0271: CvInfoType(0x0271,  "T_PFWCHAR",      "I",    4,   False,  0x0071,  True ), # 16:16 far pointer to a wide char
    0x0371: CvInfoType(0x0371,  "T_PHWCHAR",      "I",    4,   False,  0x0071,  True ), # 16:16 huge pointer to a wide char
    0x0471: CvInfoType(0x0471,  "T_32PWCHAR",     "I",    4,   False,  0x0071,  False), # 32 bit pointer to a wide char
    0x0571: CvInfoType(0x0571,  "T_32PFWCHAR",    "6x",   6,   False,  0x0071,  True ), # 16:32 pointer to a wide char
    0x0671: CvInfoType(0x0671,  "T_64PWCHAR",     "Q",    8,   False,  0x0071,  True ), # 64 bit pointer to a wide char

#      really a 16-bit unicode char

    0x007a: CvInfoType(0x007a,  "T_CHAR16",       "H",    2,   False,  None,    True ), # 16-bit unicode char
    0x017a: CvInfoType(0x017a,  "T_PCHAR16",      "H",    2,   False,  0x007a,  True ), # 16 bit pointer to a 16-bit unicode char
    0x027a: CvInfoType(0x027a,  "T_PFCHAR16",     "I",    4,   False,  0x007a,  True ), # 16:16 far pointer to a 16-bit unicode char
    0x037a: CvInfoType(0x037a,  "T_PHCHAR16",     "I",    4,   False,  0x007a,  True ), # 16:16 huge pointer to a 16-bit unicode char
    0x047a: CvInfoType(0x047a,  "T_32PCHAR16",    "I",    4,   False,  0x007a,  True ), # 32 bit pointer to a 16-bit unicode char
    0x057a: CvInfoType(0x057a,  "T_32PFCHAR16",   "6x",   6,   False,  0x007a,  True ), # 16:32 pointer to a 16-bit unicode char
    0x067a: CvInfoType(0x067a,  "T_64PCHAR16",    "Q",    8,   False,  0x007a,  True ), # 64 bit pointer to a 16-bit unicode char

#      really a 32-bit unicode char

    0x007b: CvInfoType(0x007b,  "T_CHAR32",       "I",    4,   False,  None,    True ), # 32-bit unicode char
    0x017b: CvInfoType(0x017b,  "T_PCHAR32",      "H",    2,   False,  0x007b,  True ), # 16 bit pointer to a 32-bit unicode char
    0x027b: CvInfoType(0x027b,  "T_PFCHAR32",     "I",    4,   False,  0x007b,  True ), # 16:16 far pointer to a 32-bit unicode char
    0x037b: CvInfoType(0x037b,  "T_PHCHAR32",     "I",    4,   False,  0x007b,  True ), # 16:16 huge pointer to a 32-bit unicode char
    0x047b: CvInfoType(0x047b,  "T_32PCHAR32",    "I",    4,   False,  0x007b,  True ), # 32 bit pointer to a 32-bit unicode char
    0x057b: CvInfoType(0x057b,  "T_32PFCHAR32",   "6x",   6,   False,  0x007b,  True ), # 16:32 pointer to a 32-bit unicode char
    0x067b: CvInfoType(0x067b,  "T_64PCHAR32",    "Q",    8,   False,  0x007b,  True ), # 64 bit pointer to a 32-bit unicode char

#      8 bit int types

    0x0068: CvInfoType(0x0068,  "T_INT1",         "b",    1,   False,  None,    True ), # 8 bit signed int
    0x0168: CvInfoType(0x0168,  "T_PINT1",        "H",    2,   False,  0x0068,  True ), # 16 bit pointer to 8 bit signed int
    0x0268: CvInfoType(0x0268,  "T_PFINT1",       "I",    4,   False,  0x0068,  True ), # 16:16 far pointer to 8 bit signed int
    0x0368: CvInfoType(0x0368,  "T_PHINT1",       "I",    4,   False,  0x0068,  True ), # 16:16 huge pointer to 8 bit signed int
    0x0468: CvInfoType(0x0468,  "T_32PINT1",      "I",    4,   False,  0x0068,  True ), # 32 bit pointer to 8 bit signed int
    0x0568: CvInfoType(0x0568,  "T_32PFINT1",     "6x",   6,   False,  0x0068,  True ), # 16:32 pointer to 8 bit signed int
    0x0668: CvInfoType(0x0668,  "T_64PINT1",      "Q",    8,   False,  0x0068,  True ), # 64 bit pointer to 8 bit signed int

    0x0069: CvInfoType(0x0069,  "T_UINT1",        "B",    1,   False,  None,    True ), # 8 bit unsigned int
    0x0169: CvInfoType(0x0169,  "T_PUINT1",       "H",    2,   False,  0x0069,  True ), # 16 bit pointer to 8 bit unsigned int
    0x0269: CvInfoType(0x0269,  "T_PFUINT1",      "I",    4,   False,  0x0069,  True ), # 16:16 far pointer to 8 bit unsigned int
    0x0369: CvInfoType(0x0369,  "T_PHUINT1",      "I",    4,   False,  0x0069,  True ), # 16:16 huge pointer to 8 bit unsigned int
    0x0469: CvInfoType(0x0469,  "T_32PUINT1",     "I",    4,   False,  0x0069,  True ), # 32 bit pointer to 8 bit unsigned int
    0x0569: CvInfoType(0x0569,  "T_32PFUINT1",    "6x",   6,   False,  0x0069,  True ), # 16:32 pointer to 8 bit unsigned int
    0x0669: CvInfoType(0x0669,  "T_64PUINT1",     "Q",    8,   False,  0x0069,  True ), # 64 bit pointer to 8 bit unsigned int


#      16 bit short types

    0x0011: CvInfoType(0x0011,  "T_SHORT",        "h",    2,   False,  None,    False), # 16 bit signed
    0x0111: CvInfoType(0x0111,  "T_PSHORT",       "H",    2,   False,  0x0011,  True ), # 16 bit pointer to 16 bit signed
    0x0211: CvInfoType(0x0211,  "T_PFSHORT",      "I",    4,   False,  0x0011,  True ), # 16:16 far pointer to 16 bit signed
    0x0311: CvInfoType(0x0311,  "T_PHSHORT",      "I",    4,   False,  0x0011,  True ), # 16:16 huge pointer to 16 bit signed
    0x0411: CvInfoType(0x0411,  "T_32PSHORT",     "I",    4,   False,  0x0011,  False), # 32 bit pointer to 16 bit signed
    0x0511: CvInfoType(0x0511,  "T_32PFSHORT",    "6x",   6,   False,  0x0011,  True ), # 16:32 pointer to 16 bit signed
    0x0611: CvInfoType(0x0611,  "T_64PSHORT",     "Q",    8,   False,  0x0011,  True ), # 64 bit pointer to 16 bit signed

    0x0021: CvInfoType(0x0021,  "T_USHORT",       "H",    2,   False,  None,    False), # 16 bit unsigned
    0x0121: CvInfoType(0x0121,  "T_PUSHORT",      "H",    2,   False,  0x0021,  True ), # 16 bit pointer to 16 bit unsigned
    0x0221: CvInfoType(0x0221,  "T_PFUSHORT",     "I",    4,   False,  0x0021,  True ), # 16:16 far pointer to 16 bit unsigned
    0x0321: CvInfoType(0x0321,  "T_PHUSHORT",     "I",    4,   False,  0x0021,  True ), # 16:16 huge pointer to 16 bit unsigned
    0x0421: CvInfoType(0x0421,  "T_32PUSHORT",    "I",    4,   False,  0x0021,  False), # 32 bit pointer to 16 bit unsigned
    0x0521: CvInfoType(0x0521,  "T_32PFUSHORT",   "6x",   6,   False,  0x0021,  True ), # 16:32 pointer to 16 bit unsigned
    0x0621: CvInfoType(0x0621,  "T_64PUSHORT",    "Q",    8,   False,  0x0021,  True ), # 64 bit pointer to 16 bit unsigned


#      16 bit int types

    0x0072: CvInfoType(0x0072,  "T_INT2",         "h",    2,   False,  None,    True ), # 16 bit signed int
    0x0172: CvInfoType(0x0172,  "T_PINT2",        "H",    2,   False,  0x0072,  True ), # 16 bit pointer to 16 bit signed int
    0x0272: CvInfoType(0x0272,  "T_PFINT2",       "I",    4,   False,  0x0072,  True ), # 16:16 far pointer to 16 bit signed int
    0x0372: CvInfoType(0x0372,  "T_PHINT2",       "I",    4,   False,  0x0072,  True ), # 16:16 huge pointer to 16 bit signed int
    0x0472: CvInfoType(0x0472,  "T_32PINT2",      "I",    4,   False,  0x0072,  True ), # 32 bit pointer to 16 bit signed int
    0x0572: CvInfoType(0x0572,  "T_32PFINT2",     "6x",   6,   False,  0x0072,  True ), # 16:32 pointer to 16 bit signed int
    0x0672: CvInfoType(0x0672,  "T_64PINT2",      "Q",    8,   False,  0x0072,  True ), # 64 bit pointer to 16 bit signed int

    0x0073: CvInfoType(0x0073,  "T_UINT2",        "H",    2,   False,  None,    True ), # 16 bit unsigned int
    0x0173: CvInfoType(0x0173,  "T_PUINT2",       "H",    2,   False,  0x0073,  True ), # 16 bit pointer to 16 bit unsigned int
    0x0273: CvInfoType(0x0273,  "T_PFUINT2",      "I",    4,   False,  0x0073,  True ), # 16:16 far pointer to 16 bit unsigned int
    0x0373: CvInfoType(0x0373,  "T_PHUINT2",      "I",    4,   False,  0x0073,  True ), # 16:16 huge pointer to 16 bit unsigned int
    0x0473: CvInfoType(0x0473,  "T_32PUINT2",     "I",    4,   False,  0x0073,  True ), # 32 bit pointer to 16 bit unsigned int
    0x0573: CvInfoType(0x0573,  "T_32PFUINT2",    "6x",   6,   False,  0x0073,  True ), # 16:32 pointer to 16 bit unsigned int
    0x0673: CvInfoType(0x0673,  "T_64PUINT2",     "Q",    8,   False,  0x0073,  True ), # 64 bit pointer to 16 bit unsigned int


#      32 bit long types

    0x0012: CvInfoType(0x0012,  "T_LONG",         "l",    4,   False,  None,    False), # 32 bit signed
    0x0112: CvInfoType(0x0112,  "T_PLONG",        "H",    2,   False,  0x0112,  True ), # 16 bit pointer to 32 bit signed
    0x0212: CvInfoType(0x0212,  "T_PFLONG",       "I",    4,   False,  0x0112,  True ), # 16:16 far pointer to 32 bit signed
    0x0312: CvInfoType(0x0312,  "T_PHLONG",       "I",    4,   False,  0x0112,  True ), # 16:16 huge pointer to 32 bit signed
    0x0412: CvInfoType(0x0412,  "T_32PLONG",      "I",    4,   False,  0x0112,  False), # 32 bit pointer to 32 bit signed
    0x0512: CvInfoType(0x0512,  "T_32PFLONG",     "6x",   6,   False,  0x0112,  True ), # 16:32 pointer to 32 bit signed
    0x0612: CvInfoType(0x0612,  "T_64PLONG",      "Q",    8,   False,  0x0112,  True ), # 64 bit pointer to 32 bit signed

    0x0022: CvInfoType(0x0022,  "T_ULONG",        "L",    4,   False,  None,    False), # 32 bit unsigned
    0x0122: CvInfoType(0x0122,  "T_PULONG",       "H",    2,   False,  0x0022,  True ), # 16 bit pointer to 32 bit unsigned
    0x0222: CvInfoType(0x0222,  "T_PFULONG",      "I",    4,   False,  0x0022,  True ), # 16:16 far pointer to 32 bit unsigned
    0x0322: CvInfoType(0x0322,  "T_PHULONG",      "I",    4,   False,  0x0022,  True ), # 16:16 huge pointer to 32 bit unsigned
    0x0422: CvInfoType(0x0422,  "T_32PULONG",     "I",    4,   False,  0x0022,  False), # 32 bit pointer to 32 bit unsigned
    0x0522: CvInfoType(0x0522,  "T_32PFULONG",    "6x",   6,   False,  0x0022,  True ), # 16:32 pointer to 32 bit unsigned
    0x0622: CvInfoType(0x0622,  "T_64PULONG",     "Q",    8,   False,  0x0022,  True ), # 64 bit pointer to 32 bit unsigned

#      32 bit int types

    0x0074: CvInfoType(0x0074,  "T_INT4",         "i",    4,   False,  None,    False), # 32 bit signed int
    0x0174: CvInfoType(0x0174,  "T_PINT4",        "H",    2,   False,  0x0074,  True ), # 16 bit pointer to 32 bit signed int
    0x0274: CvInfoType(0x0274,  "T_PFINT4",       "I",    4,   False,  0x0074,  True ), # 16:16 far pointer to 32 bit signed int
    0x0374: CvInfoType(0x0374,  "T_PHINT4",       "I",    4,   False,  0x0074,  True ), # 16:16 huge pointer to 32 bit signed int
    0x0474: CvInfoType(0x0474,  "T_32PINT4",      "I",    4,   False,  0x0074,  False), # 32 bit pointer to 32 bit signed int
    0x0574: CvInfoType(0x0574,  "T_32PFINT4",     "6x",   6,   False,  0x0074,  True ), # 16:32 pointer to 32 bit signed int
    0x0674: CvInfoType(0x0674,  "T_64PINT4",      "Q",    8,   False,  0x0074,  True ), # 64 bit pointer to 32 bit signed int

    0x0075: CvInfoType(0x0075,  "T_UINT4",        "I",    4,   False,  None,    False), # 32 bit unsigned int
    0x0175: CvInfoType(0x0175,  "T_PUINT4",       "H",    2,   False,  0x0075,  True ), # 16 bit pointer to 32 bit unsigned int
    0x0275: CvInfoType(0x0275,  "T_PFUINT4",      "I",    4,   False,  0x0075,  True ), # 16:16 far pointer to 32 bit unsigned int
    0x0375: CvInfoType(0x0375,  "T_PHUINT4",      "I",    4,   False,  0x0075,  True ), # 16:16 huge pointer to 32 bit unsigned int
    0x0475: CvInfoType(0x0475,  "T_32PUINT4",     "I",    4,   False,  0x0075,  False), # 32 bit pointer to 32 bit unsigned int
    0x0575: CvInfoType(0x0575,  "T_32PFUINT4",    "6x",   6,   False,  0x0075,  True ), # 16:32 pointer to 32 bit unsigned int
    0x0675: CvInfoType(0x0675,  "T_64PUINT4",     "Q",    8,   False,  0x0075,  True ), # 64 bit pointer to 32 bit unsigned int


#      64 bit quad types

    0x0013: CvInfoType(0x0013,  "T_QUAD",         "q",    8,   False,  None,    False), # 64 bit signed
    0x0113: CvInfoType(0x0113,  "T_PQUAD",        "H",    2,   False,  0x0013,  True ), # 16 bit pointer to 64 bit signed
    0x0213: CvInfoType(0x0213,  "T_PFQUAD",       "I",    4,   False,  0x0013,  True ), # 16:16 far pointer to 64 bit signed
    0x0313: CvInfoType(0x0313,  "T_PHQUAD",       "I",    4,   False,  0x0013,  True ), # 16:16 huge pointer to 64 bit signed
    0x0413: CvInfoType(0x0413,  "T_32PQUAD",      "I",    4,   False,  0x0013,  False), # 32 bit pointer to 64 bit signed
    0x0513: CvInfoType(0x0513,  "T_32PFQUAD",     "6x",   6,   False,  0x0013,  True ), # 16:32 pointer to 64 bit signed
    0x0613: CvInfoType(0x0613,  "T_64PQUAD",      "Q",    8,   False,  0x0013,  True ), # 64 bit pointer to 64 bit signed

    0x0023: CvInfoType(0x0023,  "T_UQUAD",        "Q",    8,   False,  None,    False), # 64 bit unsigned
    0x0123: CvInfoType(0x0123,  "T_PUQUAD",       "H",    2,   False,  0x0023,  True ), # 16 bit pointer to 64 bit unsigned
    0x0223: CvInfoType(0x0223,  "T_PFUQUAD",      "I",    4,   False,  0x0023,  True ), # 16:16 far pointer to 64 bit unsigned
    0x0323: CvInfoType(0x0323,  "T_PHUQUAD",      "I",    4,   False,  0x0023,  True ), # 16:16 huge pointer to 64 bit unsigned
    0x0423: CvInfoType(0x0423,  "T_32PUQUAD",     "I",    4,   False,  0x0023,  False), # 32 bit pointer to 64 bit unsigned
    0x0523: CvInfoType(0x0523,  "T_32PFUQUAD",    "6x",   6,   False,  0x0023,  True ), # 16:32 pointer to 64 bit unsigned
    0x0623: CvInfoType(0x0623,  "T_64PUQUAD",     "Q",    8,   False,  0x0023,  True ), # 64 bit pointer to 64 bit unsigned


#      64 bit int types

    0x0076: CvInfoType(0x0076,  "T_INT8",         "q",    8,   False,  None,    True ), # 64 bit signed int
    0x0176: CvInfoType(0x0176,  "T_PINT8",        "H",    2,   False,  0x0076,  True ), # 16 bit pointer to 64 bit signed int
    0x0276: CvInfoType(0x0276,  "T_PFINT8",       "I",    4,   False,  0x0076,  True ), # 16:16 far pointer to 64 bit signed int
    0x0376: CvInfoType(0x0376,  "T_PHINT8",       "I",    4,   False,  0x0076,  True ), # 16:16 huge pointer to 64 bit signed int
    0x0476: CvInfoType(0x0476,  "T_32PINT8",      "I",    4,   False,  0x0076,  True ), # 32 bit pointer to 64 bit signed int
    0x0576: CvInfoType(0x0576,  "T_32PFINT8",     "6x",   6,   False,  0x0076,  True ), # 16:32 pointer to 64 bit signed int
    0x0676: CvInfoType(0x0676,  "T_64PINT8",      "Q",    8,   False,  0x0076,  True ), # 64 bit pointer to 64 bit signed int

    0x0077: CvInfoType(0x0077,  "T_UINT8",        "Q",    8,   False,  None,    True ), # 64 bit unsigned int
    0x0177: CvInfoType(0x0177,  "T_PUINT8",       "H",    2,   False,  0x0077,  True ), # 16 bit pointer to 64 bit unsigned int
    0x0277: CvInfoType(0x0277,  "T_PFUINT8",      "I",    4,   False,  0x0077,  True ), # 16:16 far pointer to 64 bit unsigned int
    0x0377: CvInfoType(0x0377,  "T_PHUINT8",      "I",    4,   False,  0x0077,  True ), # 16:16 huge pointer to 64 bit unsigned int
    0x0477: CvInfoType(0x0477,  "T_32PUINT8",     "I",    4,   False,  0x0077,  True ), # 32 bit pointer to 64 bit unsigned int
    0x0577: CvInfoType(0x0577,  "T_32PFUINT8",    "6x",   6,   False,  0x0077,  True ), # 16:32 pointer to 64 bit unsigned int
    0x0677: CvInfoType(0x0677,  "T_64PUINT8",     "Q",    8,   False,  0x0077,  True ), # 64 bit pointer to 64 bit unsigned int


#      128 bit octet types

    0x0014: CvInfoType(0x0014,  "T_OCT",          "16B",  16,  False,  None,    True ), # 128 bit signed
    0x0114: CvInfoType(0x0114,  "T_POCT",         "H",    2,   False,  0x0014,  True ), # 16 bit pointer to 128 bit signed
    0x0214: CvInfoType(0x0214,  "T_PFOCT",        "I",    4,   False,  0x0014,  True ), # 16:16 far pointer to 128 bit signed
    0x0314: CvInfoType(0x0314,  "T_PHOCT",        "I",    4,   False,  0x0014,  True ), # 16:16 huge pointer to 128 bit signed
    0x0414: CvInfoType(0x0414,  "T_32POCT",       "I",    4,   False,  0x0014,  True ), # 32 bit pointer to 128 bit signed
    0x0514: CvInfoType(0x0514,  "T_32PFOCT",      "6x",   6,   False,  0x0014,  True ), # 16:32 pointer to 128 bit signed
    0x0614: CvInfoType(0x0614,  "T_64POCT",       "Q",    8,   False,  0x0014,  True ), # 64 bit pointer to 128 bit signed

    0x0024: CvInfoType(0x0024,  "T_UOCT",         "16B",  16,  False,  None,    True ), # 128 bit unsigned
    0x0124: CvInfoType(0x0124,  "T_PUOCT",        "H",    2,   False,  0x0024,  True ), # 16 bit pointer to 128 bit unsigned
    0x0224: CvInfoType(0x0224,  "T_PFUOCT",       "I",    4,   False,  0x0024,  True ), # 16:16 far pointer to 128 bit unsigned
    0x0324: CvInfoType(0x0324,  "T_PHUOCT",       "I",    4,   False,  0x0024,  True ), # 16:16 huge pointer to 128 bit unsigned
    0x0424: CvInfoType(0x0424,  "T_32PUOCT",      "I",    4,   False,  0x0024,  True ), # 32 bit pointer to 128 bit unsigned
    0x0524: CvInfoType(0x0524,  "T_32PFUOCT",     "6x",   6,   False,  0x0024,  True ), # 16:32 pointer to 128 bit unsigned
    0x0624: CvInfoType(0x0624,  "T_64PUOCT",      "Q",    8,   False,  0x0024,  True ), # 64 bit pointer to 128 bit unsigned


#      128 bit int types

    0x0078: CvInfoType(0x0078,  "T_INT16",        "16B",  16,  False,  None,    True ), # 128 bit signed int
    0x0178: CvInfoType(0x0178,  "T_PINT16",       "H",    2,   False,  0x0078,  True ), # 16 bit pointer to 128 bit signed int
    0x0278: CvInfoType(0x0278,  "T_PFINT16",      "I",    4,   False,  0x0078,  True ), # 16:16 far pointer to 128 bit signed int
    0x0378: CvInfoType(0x0378,  "T_PHINT16",      "I",    4,   False,  0x0078,  True ), # 16:16 huge pointer to 128 bit signed int
    0x0478: CvInfoType(0x0478,  "T_32PINT16",     "I",    4,   False,  0x0078,  True ), # 32 bit pointer to 128 bit signed int
    0x0578: CvInfoType(0x0578,  "T_32PFINT16",    "6x",   6,   False,  0x0078,  True ), # 16:32 pointer to 128 bit signed int
    0x0678: CvInfoType(0x0678,  "T_64PINT16",     "Q",    8,   False,  0x0078,  True ), # 64 bit pointer to 128 bit signed int

    0x0079: CvInfoType(0x0079,  "T_UINT16",       "16B",  16,   False,  None,   True ), # 128 bit unsigned int
    0x0179: CvInfoType(0x0179,  "T_PUINT16",      "H",    2,   False,  0x0079,  True ), # 16 bit pointer to 128 bit unsigned int
    0x0279: CvInfoType(0x0279,  "T_PFUINT16",     "I",    4,   False,  0x0079,  True ), # 16:16 far pointer to 128 bit unsigned int
    0x0379: CvInfoType(0x0379,  "T_PHUINT16",     "I",    4,   False,  0x0079,  True ), # 16:16 huge pointer to 128 bit unsigned int
    0x0479: CvInfoType(0x0479,  "T_32PUINT16",    "I",    4,   False,  0x0079,  True ), # 32 bit pointer to 128 bit unsigned int
    0x0579: CvInfoType(0x0579,  "T_32PFUINT16",   "6x",   6,   False,  0x0079,  True ), # 16:32 pointer to 128 bit unsigned int
    0x0679: CvInfoType(0x0679,  "T_64PUINT16",    "Q",    8,   False,  0x0079,  True ), # 64 bit pointer to 128 bit unsigned int


#      16 bit real types

    0x0046: CvInfoType(0x0046,  "T_REAL16",       "2B",   2,   False,  None,    True ), # 16 bit real
    0x0146: CvInfoType(0x0146,  "T_PREAL16",      "H",    2,   False,  0x0046,  True ), # 16 bit pointer to 16 bit real
    0x0246: CvInfoType(0x0246,  "T_PFREAL16",     "I",    4,   False,  0x0046,  True ), # 16:16 far pointer to 16 bit real
    0x0346: CvInfoType(0x0346,  "T_PHREAL16",     "I",    4,   False,  0x0046,  True ), # 16:16 huge pointer to 16 bit real
    0x0446: CvInfoType(0x0446,  "T_32PREAL16",    "I",    4,   False,  0x0046,  True ), # 32 bit pointer to 16 bit real
    0x0546: CvInfoType(0x0546,  "T_32PFREAL16",   "6x",   6,   False,  0x0046,  True ), # 16:32 pointer to 16 bit real
    0x0646: CvInfoType(0x0646,  "T_64PREAL16",    "Q",    8,   False,  0x0046,  True ), # 64 bit pointer to 16 bit real


#      32 bit real types

    0x0040: CvInfoType(0x0040,  "T_REAL32",       "f",    4,   False,  None,    False), # 32 bit real
    0x0140: CvInfoType(0x0140,  "T_PREAL32",      "H",    2,   False,  0x0040,  True ), # 16 bit pointer to 32 bit real
    0x0240: CvInfoType(0x0240,  "T_PFREAL32",     "I",    4,   False,  0x0040,  True ), # 16:16 far pointer to 32 bit real
    0x0340: CvInfoType(0x0340,  "T_PHREAL32",     "I",    4,   False,  0x0040,  True ), # 16:16 huge pointer to 32 bit real
    0x0440: CvInfoType(0x0440,  "T_32PREAL32",    "I",    4,   False,  0x0040,  False), # 32 bit pointer to 32 bit real
    0x0540: CvInfoType(0x0540,  "T_32PFREAL32",   "6x",   6,   False,  0x0040,  True ), # 16:32 pointer to 32 bit real
    0x0640: CvInfoType(0x0640,  "T_64PREAL32",    "Q",    8,   False,  0x0040,  True ), # 64 bit pointer to 32 bit real


#      32 bit partial-precision real types

    0x0045: CvInfoType(0x0045,  "T_REAL32PP",     "4B",   4,   False,  None,    True ), # 32 bit PP real
    0x0145: CvInfoType(0x0145,  "T_PREAL32PP",    "H",    2,   False,  0x0045,  True ), # 16 bit pointer to 32 bit PP real
    0x0245: CvInfoType(0x0245,  "T_PFREAL32PP",   "I",    4,   False,  0x0045,  True ), # 16:16 far pointer to 32 bit PP real
    0x0345: CvInfoType(0x0345,  "T_PHREAL32PP",   "I",    4,   False,  0x0045,  True ), # 16:16 huge pointer to 32 bit PP real
    0x0445: CvInfoType(0x0445,  "T_32PREAL32PP",  "I",    4,   False,  0x0045,  True ), # 32 bit pointer to 32 bit PP real
    0x0545: CvInfoType(0x0545,  "T_32PFREAL32PP", "6x",   6,   False,  0x0045,  True ), # 16:32 pointer to 32 bit PP real
    0x0645: CvInfoType(0x0645,  "T_64PREAL32PP",  "Q",    8,   False,  0x0045,  True ), # 64 bit pointer to 32 bit PP real


#      48 bit real types

    0x0044: CvInfoType(0x0044,  "T_REAL48",       "6B",   6,   False,  None,    True ), # 48 bit real
    0x0144: CvInfoType(0x0144,  "T_PREAL48",      "H",    2,   False,  0x0044,  True ), # 16 bit pointer to 48 bit real
    0x0244: CvInfoType(0x0244,  "T_PFREAL48",     "I",    4,   False,  0x0044,  True ), # 16:16 far pointer to 48 bit real
    0x0344: CvInfoType(0x0344,  "T_PHREAL48",     "I",    4,   False,  0x0044,  True ), # 16:16 huge pointer to 48 bit real
    0x0444: CvInfoType(0x0444,  "T_32PREAL48",    "I",    4,   False,  0x0044,  True ), # 32 bit pointer to 48 bit real
    0x0544: CvInfoType(0x0544,  "T_32PFREAL48",   "6x",   6,   False,  0x0044,  True ), # 16:32 pointer to 48 bit real
    0x0644: CvInfoType(0x0644,  "T_64PREAL48",    "Q",    8,   False,  0x0044,  True ), # 64 bit pointer to 48 bit real


#      64 bit real types

    0x0041: CvInfoType(0x0041,  "T_REAL64",       "d",    8,   False,  None,    False), # 64 bit real
    0x0141: CvInfoType(0x0141,  "T_PREAL64",      "H",    2,   False,  0x0041,  True ), # 16 bit pointer to 64 bit real
    0x0241: CvInfoType(0x0241,  "T_PFREAL64",     "I",    4,   False,  0x0041,  True ), # 16:16 far pointer to 64 bit real
    0x0341: CvInfoType(0x0341,  "T_PHREAL64",     "I",    4,   False,  0x0041,  True ), # 16:16 huge pointer to 64 bit real
    0x0441: CvInfoType(0x0441,  "T_32PREAL64",    "I",    4,   False,  0x0041,  False), # 32 bit pointer to 64 bit real
    0x0541: CvInfoType(0x0541,  "T_32PFREAL64",   "6x",   6,   False,  0x0041,  True ), # 16:32 pointer to 64 bit real
    0x0641: CvInfoType(0x0641,  "T_64PREAL64",    "Q",    8,   False,  0x0041,  True ), # 64 bit pointer to 64 bit real


#      80 bit real types

    0x0042: CvInfoType(0x0042,  "T_REAL80",       "10B",  10,  False,  None,    True ), # 80 bit real
    0x0142: CvInfoType(0x0142,  "T_PREAL80",      "H",    2,   False,  0x0042,  True ), # 16 bit pointer to 80 bit real
    0x0242: CvInfoType(0x0242,  "T_PFREAL80",     "I",    4,   False,  0x0042,  True ), # 16:16 far pointer to 80 bit real
    0x0342: CvInfoType(0x0342,  "T_PHREAL80",     "I",    4,   False,  0x0042,  True ), # 16:16 huge pointer to 80 bit real
    0x0442: CvInfoType(0x0442,  "T_32PREAL80",    "I",    4,   False,  0x0042,  True ), # 32 bit pointer to 80 bit real
    0x0542: CvInfoType(0x0542,  "T_32PFREAL80",   "6x",   6,   False,  0x0042,  True ), # 16:32 pointer to 80 bit real
    0x0642: CvInfoType(0x0642,  "T_64PREAL80",    "Q",    8,   False,  0x0042,  True ), # 64 bit pointer to 80 bit real


#      128 bit real types

    0x0043: CvInfoType(0x0043,  "T_REAL128",      "16B",  16,  False,  None,    True ), # 128 bit real
    0x0143: CvInfoType(0x0143,  "T_PREAL128",     "H",    2,   False,  0x0043,  True ), # 16 bit pointer to 128 bit real
    0x0243: CvInfoType(0x0243,  "T_PFREAL128",    "I",    4,   False,  0x0043,  True ), # 16:16 far pointer to 128 bit real
    0x0343: CvInfoType(0x0343,  "T_PHREAL128",    "I",    4,   False,  0x0043,  True ), # 16:16 huge pointer to 128 bit real
    0x0443: CvInfoType(0x0443,  "T_32PREAL128",   "I",    4,   False,  0x0043,  True ), # 32 bit pointer to 128 bit real
    0x0543: CvInfoType(0x0543,  "T_32PFREAL128",  "6x",   6,   False,  0x0043,  True ), # 16:32 pointer to 128 bit real
    0x0643: CvInfoType(0x0643,  "T_64PREAL128",   "Q",    8,   False,  0x0043,  True ), # 64 bit pointer to 128 bit real


#      32 bit complex types

    0x0050: CvInfoType(0x0050,  "T_CPLX32",       "4B",   4,   False,  None,    True ), # 32 bit complex
    0x0150: CvInfoType(0x0150,  "T_PCPLX32",      "H",    2,   False,  0x0050,  True ), # 16 bit pointer to 32 bit complex
    0x0250: CvInfoType(0x0250,  "T_PFCPLX32",     "I",    4,   False,  0x0050,  True ), # 16:16 far pointer to 32 bit complex
    0x0350: CvInfoType(0x0350,  "T_PHCPLX32",     "I",    4,   False,  0x0050,  True ), # 16:16 huge pointer to 32 bit complex
    0x0450: CvInfoType(0x0450,  "T_32PCPLX32",    "I",    4,   False,  0x0050,  True ), # 32 bit pointer to 32 bit complex
    0x0550: CvInfoType(0x0550,  "T_32PFCPLX32",   "6x",   6,   False,  0x0050,  True ), # 16:32 pointer to 32 bit complex
    0x0650: CvInfoType(0x0650,  "T_64PCPLX32",    "Q",    8,   False,  0x0050,  True ), # 64 bit pointer to 32 bit complex


#      64 bit complex types

    0x0051: CvInfoType(0x0051,  "T_CPLX64",       "F",    8,   False,  None,    True ), # 64 bit complex
    0x0151: CvInfoType(0x0151,  "T_PCPLX64",      "H",    2,   False,  0x0051,  True ), # 16 bit pointer to 64 bit complex
    0x0251: CvInfoType(0x0251,  "T_PFCPLX64",     "I",    4,   False,  0x0051,  True ), # 16:16 far pointer to 64 bit complex
    0x0351: CvInfoType(0x0351,  "T_PHCPLX64",     "I",    4,   False,  0x0051,  True ), # 16:16 huge pointer to 64 bit complex
    0x0451: CvInfoType(0x0451,  "T_32PCPLX64",    "I",    4,   False,  0x0051,  True ), # 32 bit pointer to 64 bit complex
    0x0551: CvInfoType(0x0551,  "T_32PFCPLX64",   "6x",   6,   False,  0x0051,  True ), # 16:32 pointer to 64 bit complex
    0x0651: CvInfoType(0x0651,  "T_64PCPLX64",    "Q",    8,   False,  0x0051,  True ), # 64 bit pointer to 64 bit complex


#      80 bit complex types

    0x0052: CvInfoType(0x0052,  "T_CPLX80",       "10B",  10,  False,  None,    True ), # 80 bit complex
    0x0152: CvInfoType(0x0152,  "T_PCPLX80",      "H",    2,   False,  0x0052,  True ), # 16 bit pointer to 80 bit complex
    0x0252: CvInfoType(0x0252,  "T_PFCPLX80",     "I",    4,   False,  0x0052,  True ), # 16:16 far pointer to 80 bit complex
    0x0352: CvInfoType(0x0352,  "T_PHCPLX80",     "I",    4,   False,  0x0052,  True ), # 16:16 huge pointer to 80 bit complex
    0x0452: CvInfoType(0x0452,  "T_32PCPLX80",    "I",    4,   False,  0x0052,  True ), # 32 bit pointer to 80 bit complex
    0x0552: CvInfoType(0x0552,  "T_32PFCPLX80",   "6x",   6,   False,  0x0052,  True ), # 16:32 pointer to 80 bit complex
    0x0652: CvInfoType(0x0652,  "T_64PCPLX80",    "Q",    8,   False,  0x0052,  True ), # 64 bit pointer to 80 bit complex


#      128 bit complex types

    0x0053: CvInfoType(0x0053,  "T_CPLX128",      "D",    16,  False,  None,    True ), # 128 bit complex
    0x0153: CvInfoType(0x0153,  "T_PCPLX128",     "H",    2,   False,  0x0053,  True ), # 16 bit pointer to 128 bit complex
    0x0253: CvInfoType(0x0253,  "T_PFCPLX128",    "I",    4,   False,  0x0053,  True ), # 16:16 far pointer to 128 bit complex
    0x0353: CvInfoType(0x0353,  "T_PHCPLX128",    "I",    4,   False,  0x0053,  True ), # 16:16 huge pointer to 128 bit real
    0x0453: CvInfoType(0x0453,  "T_32PCPLX128",   "I",    4,   False,  0x0053,  True ), # 32 bit pointer to 128 bit complex
    0x0553: CvInfoType(0x0553,  "T_32PFCPLX128",  "6x",   6,   False,  0x0053,  True ), # 16:32 pointer to 128 bit complex
    0x0653: CvInfoType(0x0653,  "T_64PCPLX128",   "Q",    8,   False,  0x0053,  True ), # 64 bit pointer to 128 bit complex


#      boolean types

    0x0030: CvInfoType(0x0030,  "T_BOOL08",       "B",    1,   False,  None,    True ), # 8 bit boolean
    0x0130: CvInfoType(0x0130,  "T_PBOOL08",      "H",    2,   False,  0x0030,  True ), # 16 bit pointer to  8 bit boolean
    0x0230: CvInfoType(0x0230,  "T_PFBOOL08",     "I",    4,   False,  0x0030,  True ), # 16:16 far pointer to  8 bit boolean
    0x0330: CvInfoType(0x0330,  "T_PHBOOL08",     "I",    4,   False,  0x0030,  True ), # 16:16 huge pointer to  8 bit boolean
    0x0430: CvInfoType(0x0430,  "T_32PBOOL08",    "I",    4,   False,  0x0030,  True ), # 32 bit pointer to 8 bit boolean
    0x0530: CvInfoType(0x0530,  "T_32PFBOOL08",   "6x",   6,   False,  0x0030,  True ), # 16:32 pointer to 8 bit boolean
    0x0630: CvInfoType(0x0630,  "T_64PBOOL08",    "Q",    8,   False,  0x0030,  True ), # 64 bit pointer to 8 bit boolean

    0x0031: CvInfoType(0x0031,  "T_BOOL16",       "H",    2,   False,  None,    True ), # 16 bit boolean
    0x0131: CvInfoType(0x0131,  "T_PBOOL16",      "H",    2,   False,  0x0031,  True ), # 16 bit pointer to 16 bit boolean
    0x0231: CvInfoType(0x0231,  "T_PFBOOL16",     "I",    4,   False,  0x0031,  True ), # 16:16 far pointer to 16 bit boolean
    0x0331: CvInfoType(0x0331,  "T_PHBOOL16",     "I",    4,   False,  0x0031,  True ), # 16:16 huge pointer to 16 bit boolean
    0x0431: CvInfoType(0x0431,  "T_32PBOOL16",    "I",    4,   False,  0x0031,  True ), # 32 bit pointer to 18 bit boolean
    0x0531: CvInfoType(0x0531,  "T_32PFBOOL16",   "6x",   6,   False,  0x0031,  True ), # 16:32 pointer to 16 bit boolean
    0x0631: CvInfoType(0x0631,  "T_64PBOOL16",    "Q",    8,   False,  0x0031,  True ), # 64 bit pointer to 18 bit boolean

    0x0032: CvInfoType(0x0032,  "T_BOOL32",       "I",    4,   False,  None,    True ), # 32 bit boolean
    0x0132: CvInfoType(0x0132,  "T_PBOOL32",      "H",    2,   False,  0x0032,  True ), # 16 bit pointer to 32 bit boolean
    0x0232: CvInfoType(0x0232,  "T_PFBOOL32",     "I",    4,   False,  0x0032,  True ), # 16:16 far pointer to 32 bit boolean
    0x0332: CvInfoType(0x0332,  "T_PHBOOL32",     "I",    4,   False,  0x0032,  True ), # 16:16 huge pointer to 32 bit boolean
    0x0432: CvInfoType(0x0432,  "T_32PBOOL32",    "I",    4,   False,  0x0032,  True ), # 32 bit pointer to 32 bit boolean
    0x0532: CvInfoType(0x0532,  "T_32PFBOOL32",   "6x",   6,   False,  0x0032,  True ), # 16:32 pointer to 32 bit boolean
    0x0632: CvInfoType(0x0632,  "T_64PBOOL32",    "Q",    8,   False,  0x0032,  True ), # 64 bit pointer to 32 bit boolean

    0x0033: CvInfoType(0x0033,  "T_BOOL64",       "Q",    8,   False,  None,    True ), # 64 bit boolean
    0x0133: CvInfoType(0x0133,  "T_PBOOL64",      "H",    2,   False,  0x0033,  True ), # 16 bit pointer to 64 bit boolean
    0x0233: CvInfoType(0x0233,  "T_PFBOOL64",     "I",    4,   False,  0x0033,  True ), # 16:16 far pointer to 64 bit boolean
    0x0333: CvInfoType(0x0333,  "T_PHBOOL64",     "I",    4,   False,  0x0033,  True ), # 16:16 huge pointer to 64 bit boolean
    0x0433: CvInfoType(0x0433,  "T_32PBOOL64",    "I",    4,   False,  0x0033,  True ), # 32 bit pointer to 64 bit boolean
    0x0533: CvInfoType(0x0533,  "T_32PFBOOL64",   "6x",   6,   False,  0x0033,  True ), # 16:32 pointer to 64 bit boolean
    0x0633: CvInfoType(0x0633,  "T_64PBOOL64",    "Q",    8,   False,  0x0033,  True ), # 64 bit pointer to 64 bit boolean


#      ???

    0x01f0: CvInfoType(0x01f0,  "T_NCVPTR",       "",     0,   True,   None,    True ), # CV Internal type for created near pointers
    0x02f0: CvInfoType(0x02f0,  "T_FCVPTR",       "",     0,   True,   None,    True ), # CV Internal type for created far pointers
    0x03f0: CvInfoType(0x03f0,  "T_HCVPTR",       "",     0,   True,   None,    True ), # CV Internal type for created huge pointers
    0x04f0: CvInfoType(0x04f0,  "T_32NCVPTR",     "",     0,   True,   None,    True ), # CV Internal type for created near 32-bit pointers
    0x05f0: CvInfoType(0x05f0,  "T_32FCVPTR",     "",     0,   True,   None,    True ), # CV Internal type for created far 32-bit pointers
    0x06f0: CvInfoType(0x06f0,  "T_64NCVPTR",     "",     0,   True,   None,    True ), # CV Internal type for created near 64-bit pointers
}
# fmt: on


# Just add the key at the front to get a CvInfoType tuple.
_UNKNOWN_TYPE_ATTRS = ("???", "", 0, False, None, True)


def cvinfo_type_name(key: int) -> str:
    return _TYPE_ENUM_E.get(key, CvInfoType(key, *_UNKNOWN_TYPE_ATTRS)).name


def get_cvinfo(key: int) -> CvInfoType:
    return _TYPE_ENUM_E[key]
