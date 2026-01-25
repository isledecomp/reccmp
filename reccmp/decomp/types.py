"""Types shared by other modules"""

from enum import IntEnum


class EntityType(IntEnum):
    """Broadly tells us what kind of comparison is required for this symbol."""

    FUNCTION = 1
    DATA = 2
    POINTER = 3
    STRING = 4
    VTABLE = 5
    FLOAT = 6
    IMPORT = 7
    LINE = 8
    THUNK = 9
    VTORDISP = 10
    WIDECHAR = 11
    IMPORT_THUNK = 12
    LABEL = 13
    OFFSET = 14


class ImageId(IntEnum):
    ORIG = 0
    RECOMP = 1
