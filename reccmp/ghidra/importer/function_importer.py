# This file can only be imported successfully when run from Ghidra using Ghidrathon.

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import logging
from abc import ABC, abstractmethod
from typing import Iterable, Sequence

from ghidra.program.model.listing import Function, Parameter
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    TypeDef,
    TypedefDataType,
    Pointer,
    ComponentOffsetSettingsDefinition,
)
from reccmp.cvdump.types import CVInfoTypeEnum

from .pdb_extraction import (
    PdbFunction,
    CppRegisterSymbol,
    CppStackSymbol,
)
from .ghidra_helper import (
    add_data_type_or_reuse_existing,
    get_class_namespace_and_name,
    get_or_add_pointer_type,
)

from .exceptions import (
    StackOffsetMismatchError,
    ReccmpGhidraException,
    TypeNotImplementedError,
)
from .type_importer import PdbTypeImporter
from .types import CompiledRegexReplacements

logger = logging.getLogger(__name__)


class PdbFunctionImporter(ABC):
    """A representation of a function from the PDB with each type replaced by a Ghidra type instance."""

    def __init__(
        self,
        api: FlatProgramAPI,
        func: PdbFunction,
        type_importer: "PdbTypeImporter",
        name_substitutions: CompiledRegexReplacements,
    ):
        self.api = api
        self.match_info = func.match_info
        self.type_importer = type_importer

        assert self.match_info.name is not None

        self.namespace, self.name = get_class_namespace_and_name(
            self.api,
            self.match_info.name,
        )

        for pattern, substitution in name_substitutions:
            new_name = pattern.sub(substitution, self.name)
            if new_name != self.name:
                logger.debug(
                    "Substituting function name: %s -> %s", self.name, new_name
                )
                self.name = new_name

    def get_full_name(self) -> str:
        return f"{self.namespace.getName()}::{self.name}"

    @staticmethod
    def build(
        api: FlatProgramAPI,
        func: PdbFunction,
        type_importer: "PdbTypeImporter",
        name_substitutions: CompiledRegexReplacements,
    ):
        return (
            ThunkPdbFunctionImport(api, func, type_importer, name_substitutions)
            if func.signature is None
            else FullPdbFunctionImporter(api, func, type_importer, name_substitutions)
        )

    @abstractmethod
    def matches_ghidra_function(self, ghidra_function: Function) -> bool: ...

    @abstractmethod
    def overwrite_ghidra_function(self, ghidra_function: Function): ...


class ThunkPdbFunctionImport(PdbFunctionImporter):
    """For importing thunk functions (like vtordisp or debug build thunks) into Ghidra.
    Only the name of the function will be imported."""

    def matches_ghidra_function(self, ghidra_function: Function) -> bool:
        name_match = self.name == ghidra_function.getName()
        namespace_match = self.namespace == ghidra_function.getParentNamespace()

        logger.debug("Matches: namespace=%s name=%s", namespace_match, name_match)

        return name_match and namespace_match

    def overwrite_ghidra_function(self, ghidra_function: Function):
        ghidra_function.setName(self.name, SourceType.USER_DEFINED)
        ghidra_function.setParentNamespace(self.namespace)


# pylint: disable=too-many-instance-attributes
class FullPdbFunctionImporter(PdbFunctionImporter):
    """For importing functions into Ghidra where all information are available."""

    def __init__(
        self,
        api: FlatProgramAPI,
        func: PdbFunction,
        type_importer: "PdbTypeImporter",
        name_substitutions: CompiledRegexReplacements,
    ):
        super().__init__(api, func, type_importer, name_substitutions)

        assert func.signature is not None
        self.signature = func.signature

        self.is_stub = func.is_stub

        if self.signature.class_type is not None:
            # Import the base class so the namespace exists
            self.type_importer.import_pdb_type_into_ghidra(self.signature.class_type)

        self.return_type = type_importer.import_pdb_type_into_ghidra(
            self.signature.return_type
        )

        if CVInfoTypeEnum.T_NOTYPE in self.signature.arglist:
            # Variadric functions have a T_NOTYPE as their last argument
            raise TypeNotImplementedError(
                f"Function '{self.get_full_name()}' is probably variadric, which is not implemented yet."
            )

        self.arguments: Sequence[ParameterImpl] = [
            ParameterImpl(
                f"param{index}",
                type_importer.import_pdb_type_into_ghidra(type_name),
                api.getCurrentProgram(),
            )
            for (index, type_name) in enumerate(self.signature.arglist)
        ]

    def matches_ghidra_function(self, ghidra_function: Function) -> bool:
        """Checks whether this function declaration already matches the description in Ghidra"""
        name_match = self.name == ghidra_function.getName()
        namespace_match = self.namespace == ghidra_function.getParentNamespace()
        ghidra_return_type = ghidra_function.getReturnType()
        return_type_match = self.return_type == ghidra_return_type

        # Handle edge case: Return type X that is larger than the return register.
        # In that case, the function returns `X*` and has another argument `X* __return_storage_ptr`.
        if (
            (not return_type_match)
            and (self.return_type.getLength() > 4)
            and (
                get_or_add_pointer_type(self.api, self.return_type)
                == ghidra_return_type
            )
            and any(
                param
                for param in ghidra_function.getParameters()
                if param.getName() == "__return_storage_ptr__"
            )
        ):
            logger.debug(
                "%s has a return type larger than 4 bytes", self.get_full_name()
            )
            return_type_match = True

        # match arguments: decide if thiscall or not, and whether the `this` type matches
        calling_convention_match = (
            self.signature.call_type == ghidra_function.getCallingConventionName()
        )

        ghidra_params_without_this = list(ghidra_function.getParameters())

        if calling_convention_match and self.signature.call_type == "__thiscall":
            this_argument = ghidra_params_without_this.pop(0)
            calling_convention_match = self._this_type_match(this_argument)

        if self.is_stub:
            # We do not import the argument list for stubs, so it should be excluded in matches
            args_match = True
        elif calling_convention_match:
            args_match = self._parameter_lists_match(ghidra_params_without_this)
        else:
            args_match = False

        logger.debug(
            "Matches: namespace=%s name=%s return_type=%s calling_convention=%s args=%s",
            namespace_match,
            name_match,
            return_type_match,
            calling_convention_match,
            "ignored" if self.is_stub else args_match,
        )

        return (
            name_match
            and namespace_match
            and return_type_match
            and calling_convention_match
            and args_match
        )

    def _this_type_match(self, this_parameter: Parameter) -> bool:
        if this_parameter.getName() != "this":
            logger.info("Expected first argument to be `this` in __thiscall")
            return False

        if self.signature.this_adjust != 0:
            # In this case, the `this` argument should be custom defined
            if not isinstance(this_parameter.getDataType(), TypeDef):
                logger.info(
                    "`this` argument is not a typedef while `this adjust` = %d",
                    self.signature.this_adjust,
                )
                return False
            # We are not checking for the _correct_ `this` type here, which we could do in the future

        return True

    def _parameter_lists_match(self, ghidra_params: "list[Parameter]") -> bool:
        # Remove return storage pointer from comparison if present.
        # This is relevant to returning values larger than 4 bytes, and is not mentioned in the PDB
        ghidra_params = [
            param
            for param in ghidra_params
            if param.getName() != "__return_storage_ptr__"
        ]

        if len(self.arguments) != len(ghidra_params):
            logger.info("Mismatching argument count")
            return False

        for this_arg, ghidra_arg in zip(self.arguments, ghidra_params):
            # compare argument types
            if this_arg.getDataType() != ghidra_arg.getDataType():
                logger.debug(
                    "Mismatching arg type: expected %s, found %s",
                    this_arg.getDataType(),
                    ghidra_arg.getDataType(),
                )
                return False
            # compare argument names
            stack_match = self.get_matching_stack_symbol(ghidra_arg.getStackOffset())
            if stack_match is None:
                logger.debug("Not found on stack: %s", ghidra_arg)
                return False

            if stack_match.name.startswith("__formal"):
                # "__formal" is the placeholder for arguments without a name
                continue

            if stack_match.name == "__$ReturnUdt":
                # These appear in templates and cannot be set automatically, as they are a NOTYPE
                continue

            if stack_match.name != ghidra_arg.getName():
                logger.debug(
                    "Argument name mismatch: expected %s, found %s",
                    stack_match.name,
                    ghidra_arg.getName(),
                )
                return False
        return True

    def overwrite_ghidra_function(self, ghidra_function: Function):
        """Replace the function declaration in Ghidra by the one derived from C++."""

        if ghidra_function.hasCustomVariableStorage():
            # Unfortunately, calling `ghidra_function.setCustomVariableStorage(False)`
            # leads to two `this` parameters. Therefore, we first need to remove all `this` parameters
            # and then re-generate a new one
            ghidra_function.replaceParameters(
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,  # this implicitly sets custom variable storage to False
                True,
                SourceType.USER_DEFINED,
                *[
                    param
                    for param in ghidra_function.getParameters()
                    if param.getName() != "this"
                ],
            )

        if ghidra_function.hasCustomVariableStorage():
            raise ReccmpGhidraException("Failed to disable custom variable storage.")

        ghidra_function.setName(self.name, SourceType.USER_DEFINED)
        ghidra_function.setParentNamespace(self.namespace)
        ghidra_function.setReturnType(self.return_type, SourceType.USER_DEFINED)
        ghidra_function.setCallingConvention(self.signature.call_type)

        if self.is_stub:
            logger.debug(
                "%s is a stub, skipping parameter import", self.get_full_name()
            )
        else:
            ghidra_function.replaceParameters(
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True,  # force
                SourceType.USER_DEFINED,
                *self.arguments,
            )
            self._import_parameter_names(ghidra_function)

        # Special handling for `this adjust` and virtual inheritance
        if self.signature.this_adjust != 0:
            self._set_this_adjust(ghidra_function)

    def _import_parameter_names(self, ghidra_function: Function):
        # When we call `ghidra_function.replaceParameters`, Ghidra will generate the layout.
        # Now we read the parameters again and match them against the stack layout in the PDB,
        # both to verify the layout and to set the parameter names.
        ghidra_parameters: Iterable[Parameter] = ghidra_function.getParameters()

        # Try to add Ghidra function names
        for index, param in enumerate(ghidra_parameters):
            if param.isStackVariable():
                self._rename_stack_parameter(index, param)
            else:
                if param.getName() == "this":
                    # 'this' parameters are auto-generated and cannot be changed
                    continue

                # Appears to never happen - could in theory be relevant to __fastcall__ functions,
                # which we haven't seen yet
                logger.warning(
                    "Unhandled register variable in %s", self.get_full_name()
                )
                continue

    def _rename_stack_parameter(self, index: int, param: Parameter):
        match = self.get_matching_stack_symbol(param.getStackOffset())
        if match is None:
            raise StackOffsetMismatchError(
                f"Could not find a matching symbol at offset {param.getStackOffset()} in {self.get_full_name()}"
            )

        if match.data_type == CVInfoTypeEnum.T_NOTYPE:
            logger.warning("Skipping stack parameter of type NOTYPE")
            return

        if param.getDataType() != self.type_importer.import_pdb_type_into_ghidra(
            match.data_type
        ):
            logger.error(
                "Type mismatch for parameter: %s in Ghidra, %s in PDB", param, match
            )
            return

        name = match.name
        if name == "__formal":
            # these can cause name collisions if multiple ones are present
            name = f"__formal_{index}"

        param.setName(name, SourceType.USER_DEFINED)

    def get_matching_stack_symbol(self, stack_offset: int) -> CppStackSymbol | None:
        return next(
            (
                symbol
                for symbol in self.signature.stack_symbols
                if isinstance(symbol, CppStackSymbol)
                and symbol.stack_offset == stack_offset
            ),
            None,
        )

    def get_matching_register_symbol(self, register: str) -> CppRegisterSymbol | None:
        return next(
            (
                symbol
                for symbol in self.signature.stack_symbols
                if isinstance(symbol, CppRegisterSymbol) and symbol.register == register
            ),
            None,
        )

    def _set_this_adjust(
        self,
        ghidra_function: Function,
    ):
        """
        When `this adjust` is non-zero, the pointer type of `this` needs to be replaced by an offset version.
        The offset can only be set on a typedef on the pointer. We also must enable custom storage so we can modify
        the auto-generated `this` parameter.
        """

        # Necessary in order to overwite the auto-generated `this`
        ghidra_function.setCustomVariableStorage(True)

        this_parameter = next(
            (
                param
                for param in ghidra_function.getParameters()
                if param.isRegisterVariable() and param.getName() == "this"
            ),
            None,
        )

        if this_parameter is None:
            logger.error(
                "Failed to find `this` parameter in a function with `this adjust = %d`",
                self.signature.this_adjust,
            )
        else:
            current_ghidra_type = this_parameter.getDataType()
            assert isinstance(current_ghidra_type, Pointer)
            class_name = current_ghidra_type.getDataType().getName()
            typedef_name = f"{class_name}PtrOffset0x{self.signature.this_adjust:x}"

            typedef_ghidra_type = TypedefDataType(
                current_ghidra_type.getCategoryPath(),
                typedef_name,
                current_ghidra_type,
            )
            ComponentOffsetSettingsDefinition.DEF.setValue(
                typedef_ghidra_type.getDefaultSettings(), self.signature.this_adjust
            )
            typedef_ghidra_type = add_data_type_or_reuse_existing(
                self.api, typedef_ghidra_type
            )

            this_parameter.setDataType(typedef_ghidra_type, SourceType.USER_DEFINED)
