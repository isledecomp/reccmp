"""Helper functions for interacting with the Ghidra API in tests."""

from typing import TYPE_CHECKING

from .helpers import assert_instance

# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

if TYPE_CHECKING:
    from ghidra.program.model.data import DataType, Structure


def as_structure(data_type: "DataType") -> "Structure":
    from ghidra.program.model.data import Structure

    return assert_instance(data_type, Structure)


def components_of(data_type: "DataType") -> list[tuple[int, str, str]]:
    """Returns (offset, field name, type name) for each defined component.
    This should make the tests more idiomatic because it excludes the
    `undefined` filler components.
    """
    return [
        (c.getOffset(), c.getFieldName(), c.getDataType().getName())
        for c in as_structure(data_type).getDefinedComponents()
    ]


def component(data_type: "DataType", offset: int) -> "DataType":
    """Access the Ghidra DataType for the struct member at the given offset."""
    for comp in as_structure(data_type).getDefinedComponents():
        if comp.getOffset() == offset:
            return comp.getDataType()

    raise ValueError(f"No component at offset {offset} in '{data_type.getName()}'")


def dereference(data_type: "DataType") -> "DataType":
    from ghidra.program.model.data import Pointer

    assert isinstance(data_type, Pointer)
    return data_type.getDataType()
