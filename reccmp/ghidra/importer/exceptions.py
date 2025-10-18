from typing import TYPE_CHECKING

from .entity_names import NamespacePath

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false


if TYPE_CHECKING:
    from ghidra.program.model.data import DataType


class ReccmpGhidraException(Exception):
    """
    Our own base class for exceptions.
    Makes it easier to distinguish expected and unexpected errors.
    """


class TypeNotFoundError(ReccmpGhidraException):
    def __str__(self):
        return f"Type not found in PDB: {self.args[0]}"


class TypeNotFoundInGhidraError(ReccmpGhidraException):
    def __str__(self):
        return f"Type not found in Ghidra: {self.args[0]}"


class TypeNotImplementedError(ReccmpGhidraException):
    def __str__(self):
        return f"Import not implemented for type: {self.args[0]}"


class ClassOrNamespaceNotFoundInGhidraError(ReccmpGhidraException):
    def __init__(self, namespace_path: NamespacePath):
        super().__init__(namespace_path)

    def get_namespace_str(self) -> str:
        return "::".join(self.args[0])

    def __str__(self):
        return f"Class or namespace not found in Ghidra: {self.get_namespace_str()}"


class MultipleTypesFoundInGhidraError(ReccmpGhidraException):
    def __init__(self, name: str, results: list["DataType"]):
        super().__init__(name, results)
        self.name = name
        self.results = results

    def __str__(self):
        return f"Found multiple types matching '{self.name}' in Ghidra: {self.results}"


class StackOffsetMismatchError(ReccmpGhidraException):
    pass


class StructModificationError(ReccmpGhidraException):
    def __str__(self):
        return f"Failed to modify struct in Ghidra: '{self.args[0]}'\nDetailed error: {self.__cause__}"
