"""A collection of helper functions for the interaction with Ghidra."""

import logging
import re

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.data import (
    DataType,
    DataTypeConflictHandler,
    PointerDataType,
    CategoryPath,
)
from ghidra.program.model.symbol import Namespace, SourceType

from .exceptions import (
    ClassOrNamespaceNotFoundInGhidraError,
    TypeNotFoundInGhidraError,
    MultipleTypesFoundInGhidraError,
)
from .globals import GLOBALS


logger = logging.getLogger(__name__)


def get_scalar_ghidra_type(api: FlatProgramAPI, type_name: str) -> DataType:
    """
    Get a scalar/primitive type or type not contained in a namespace.
    Note that this function may raise errors when a type by that name exists multiple times.
    Manual cleanup is needed in that case.
    """

    result = list(api.getDataTypes(type_name))
    match result:
        case []:
            raise TypeNotFoundInGhidraError(type_name)
        case [value]:
            return value
        case _:
            raise MultipleTypesFoundInGhidraError(type_name, result)


def get_ghidra_type(api: FlatProgramAPI, data_type_path: list[str]) -> DataType:
    """
    Searches for the type named `typeName` in Ghidra.

    Raises:
    - NotFoundInGhidraError
    - MultipleTypesFoundInGhidraError
    """
    # We wouldn't need this check if our typing was watertight.
    # However, the check is helpful because cvdump types are dict[str, Any],
    # so the type check misses some cases where a non-list is inserted here.
    if not isinstance(data_type_path, list):
        raise ValueError(f"Expected list[str], got {type(data_type_path)}")

    match data_type_path:
        case []:
            raise ValueError("get_data_type called with empty array")
        case [*type_path, type_name]:
            category = (
                api.getCurrentProgram()
                .getDataTypeManager()
                .getCategory(CategoryPath("/" + "/".join(type_path)))
            )
            if category is None:
                raise TypeNotFoundInGhidraError(f"{type_path} (category)")

            result = category.getDataType(type_name)
            if result is None:
                raise TypeNotFoundInGhidraError(f"{type_path}/{type_name}")

            return result
        case _:
            assert False, f"Unreachable code: {data_type_path}"


def get_or_add_pointer_type(api: FlatProgramAPI, pointee: DataType) -> DataType:
    new_pointer_data_type = PointerDataType(pointee)
    new_pointer_data_type.setCategoryPath(pointee.getCategoryPath())
    return add_data_type_or_reuse_existing(api, new_pointer_data_type)


def add_data_type_or_reuse_existing(
    api: FlatProgramAPI, new_data_type: DataType
) -> DataType:
    result_data_type = (
        api.getCurrentProgram()
        .getDataTypeManager()
        .addDataType(new_data_type, DataTypeConflictHandler.KEEP_HANDLER)
    )
    if result_data_type is not new_data_type:
        logger.debug(
            "Reusing existing data type instead of new one: %s (class: %s)",
            result_data_type,
            result_data_type.__class__,
        )
    return result_data_type


def _get_ghidra_namespace(
    api: FlatProgramAPI, namespace_hierachy: list[str]
) -> Namespace:
    """Finds a matching namespace for the given list. Returns the global namespace for an empty list."""
    namespace = api.getCurrentProgram().getGlobalNamespace()
    for part in namespace_hierachy:
        if len(part) == 0:
            continue
        namespace = api.getNamespace(namespace, part)
        if namespace is None:
            raise ClassOrNamespaceNotFoundInGhidraError(namespace_hierachy)
    return namespace


def _create_ghidra_namespace(
    api: FlatProgramAPI, namespace_hierachy: list[str]
) -> Namespace:
    namespace = api.getCurrentProgram().getGlobalNamespace()
    for part in namespace_hierachy:
        if len(part) == 0:
            continue
        namespace = api.getNamespace(namespace, part)
        if namespace is None:
            namespace = api.createNamespace(namespace, part)
    return namespace


def get_or_create_namespace(
    api: FlatProgramAPI, namespace_path: list[str]
) -> Namespace:
    """
    Returns the given namespace/class if it exists. Otherwise, the last part is created as a class,
    the rest are created as namespaces.
    """
    logger.info("Looking for namespace: '%s'", namespace_path)
    try:
        result = _get_ghidra_namespace(api, namespace_path)
        logger.debug("Found existing class/namespace %s", namespace_path)
        return result
    except ClassOrNamespaceNotFoundInGhidraError:
        logger.info("Creating class/namespace %s", namespace_path)
        # We assume that the last part belongs to a class and the rest to the namespace containing the class
        [*class_namespace_path, class_name] = namespace_path
        parent_namespace = _create_ghidra_namespace(api, class_namespace_path)
        return api.createClass(parent_namespace, class_name)


# These appear in debug builds
THUNK_OF_RE = re.compile(r"^Thunk of '(.*)'$")


def sanitize_name(name: str) -> list[str]:
    """
    Takes a full class or function name and replaces characters not accepted by Ghidra.
    Applies mostly to templates, names like `vbase destructor`, and thunks in debug build.

    Returns the sanitized name split into a path along namespaces. For example,
    `sanitize_name("a::b::c") == ["a", "b", "c"]`.
    """
    if (match := THUNK_OF_RE.fullmatch(name)) is not None:
        is_thunk = True
        name = match.group(1)
    else:
        is_thunk = False

    # Replace characters forbidden in Ghidra
    new_name = (
        name.replace("<", "[")
        .replace(">", "]")
        .replace("*", "#")
        .replace(" ", "_")
        .replace("`", "'")
    )

    # Importing function names like `FUN_10001234` into BETA10 can be confusing
    # because Ghidra's auto-generated functions look exactly the same.
    # Therefore, such function names are replaced by `LEGO_10001234` in the BETA10 import.

    # FIXME: The identification here is a crutch - we need a more reusable solution for this scenario
    if GLOBALS.target_name.upper() == "BETA10.DLL":
        new_name = re.sub(r"FUN_([0-9a-f]{8})", r"LEGO1_\1", new_name)

    if "<" in name:
        new_name = "_template_" + new_name

    # TODO: This is not correct for templates of the form a<b::c>
    new_name_split = new_name.split("::")

    if is_thunk:
        new_name_split[-1] = "_thunk_" + new_name_split[-1]

    new_name = "::".join(new_name_split)
    if new_name != name:
        logger.info(
            "Changed class or function name from '%s' to '%s' to avoid Ghidra issues",
            name,
            new_name,
        )

    return new_name_split


def get_namespace_and_name(
    api: FlatProgramAPI, name_with_namespace: str
) -> tuple[Namespace, str]:
    """
    For a given entity inside a namespace or class (e.g. `namespace::class::fn`),
    returns the appropriate Ghidra namespace and extracts the base name as a string, e.g.
    `(Namespace("namespace::class"), "fn")`. Creates the namespace if necessary.
    """
    [*namespace_path, base_name] = sanitize_name(name_with_namespace)
    namespace = get_or_create_namespace(api, namespace_path)
    return namespace, base_name


def set_ghidra_label(api: FlatProgramAPI, address: int, label_with_namespace: str):
    namespace, name = get_namespace_and_name(api, label_with_namespace)
    symbol_table = api.getCurrentProgram().getSymbolTable()
    address_hex = hex(address)
    address_ghidra = api.getAddressFactory().getAddress(address_hex)
    existing_label = symbol_table.getPrimarySymbol(address_ghidra)
    if existing_label is not None:
        existing_label_name = existing_label.getName()
        if (
            existing_label.getParentNamespace() == namespace
            and existing_label_name == name
        ):
            logger.debug(
                "Label '%s' at 0x%s already exists", label_with_namespace, address_hex
            )
        else:
            logger.debug(
                "Changing label at %s from '%s' to '%s'",
                address_hex,
                existing_label_name,
                label_with_namespace,
            )
            existing_label.setNameAndNamespace(name, namespace, SourceType.USER_DEFINED)
    else:
        logger.debug("Adding label '%s' at 0x%s", name, address_hex)
        symbol_table.createLabel(address_ghidra, name, SourceType.USER_DEFINED)
