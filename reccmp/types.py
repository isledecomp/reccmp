"""Types shared by other modules"""

from enum import IntEnum
from typing_extensions import Self


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

    @classmethod
    def variable_size_types(cls) -> set[Self]:
        """Entities with size that varies depending on recomp accuracy."""
        return {
            cls.FUNCTION,
            cls.VTABLE,
            cls.DATA,
            cls.IMPORT_THUNK,
            cls.THUNK,
            cls.VTORDISP,
        }

    @classmethod
    def solid_types(cls) -> set[Self]:
        """Entities that occupy some footprint of bytes in the binary.
        Contrast with "passenger" types that are part of a parent entity.
        For example: LINE and LABEL as part of a FUNCTION."""
        return {
            *cls.variable_size_types(),
            cls.FLOAT,
            cls.STRING,
            cls.WIDECHAR,
        }


class ImageId(IntEnum):
    ORIG = 0
    RECOMP = 1


ConcreteBuffer = bytes | bytearray | memoryview
"""
See #411 and https://docs.python.org/3.14/library/collections.abc.html#collections.abc.ByteString.

To be used when `typing.Buffer` is insufficient (e.g. when `Sized` or `Indexed` is required).
"""
