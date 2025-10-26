"""Types shared by other modules"""

from enum import IntEnum
from pathlib import Path, PurePath
from typing import NamedTuple


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


class ImageId(IntEnum):
    ORIG = 0
    RECOMP = 1


class TextContainer(NamedTuple):
    """Wrapper to abstract file access in cases where we still need a path reference."""

    path: PurePath
    text: str

    @classmethod
    def from_file(cls, path: Path, encoding: str = "utf-8") -> "TextContainer":
        with open(path, "r", encoding=encoding) as f:
            return cls(path, f.read())
