"""Types shared by other modules"""

import enum


class EntityType(enum.StrEnum):
    """Broadly tells us what kind of comparison is required for this entity."""

    ERRTYPE = enum.auto()
    UNKNOWN = enum.auto()

    FUNCTION = enum.auto()
    DATA = enum.auto()
    POINTER = enum.auto()
    STRING = enum.auto()
    VTABLE = enum.auto()
    FLOAT = enum.auto()
