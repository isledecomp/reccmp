"""A collection of helper functions for the interaction with Ghidra."""

import logging

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

from .entity_names import NamespacePath, SanitizedEntityName, sanitize_name
from .exceptions import (
    ClassOrNamespaceNotFoundInGhidraError,
    TypeNotFoundInGhidraError,
    MultipleTypesFoundInGhidraError,
)


logger = logging.getLogger(__name__)


def category_path_of(namespace_path: NamespacePath):
    return CategoryPath("/" + "/".join(namespace_path))


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


def get_ghidra_type(api: FlatProgramAPI, entity_name: SanitizedEntityName) -> DataType:
    """
    Searches for the type named `typeName` in Ghidra.

    Raises:
    - NotFoundInGhidraError
    - MultipleTypesFoundInGhidraError
    """

    category_path = category_path_of(entity_name.namespace_path)

    category = api.getCurrentProgram().getDataTypeManager().getCategory(category_path)
    if category is None:
        raise TypeNotFoundInGhidraError(f"{category_path.getPath()} (category)")

    result = category.getDataType(entity_name.base_name)
    if result is None:
        raise TypeNotFoundInGhidraError(
            f"{category_path.getPath()}/{entity_name.base_name}"
        )

    return result


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
    api: FlatProgramAPI, namespace_path: NamespacePath
) -> Namespace:
    """Finds a matching namespace for the given list. Returns the global namespace for an empty list."""
    namespace = api.getCurrentProgram().getGlobalNamespace()
    for part in namespace_path:
        if len(part) == 0:
            continue
        namespace = api.getNamespace(namespace, part)
        if namespace is None:
            raise ClassOrNamespaceNotFoundInGhidraError(namespace_path)
    return namespace


def _create_ghidra_namespace(
    api: FlatProgramAPI, namespace_path: NamespacePath
) -> Namespace:
    namespace = api.getCurrentProgram().getGlobalNamespace()
    for part in namespace_path:
        if len(part) == 0:
            continue
        namespace = api.getNamespace(namespace, part)
        if namespace is None:
            namespace = api.createNamespace(namespace, part)
    return namespace


def get_or_create_class_namespace(
    api: FlatProgramAPI, namespace_path: NamespacePath
) -> Namespace:
    """
    Classes are very similar to namespaces in Ghidra. This function returns the class/namespace if it exists.
    Otherwise, the last part is created as a class, the rest are created as namespaces.
    """
    logger.info("Looking for namespace: '%s'", namespace_path)
    try:
        result = _get_ghidra_namespace(api, namespace_path)
        logger.debug("Found existing class/namespace %s", namespace_path)
        return result
    except ClassOrNamespaceNotFoundInGhidraError:
        logger.info("Creating class %s", namespace_path)
        # We assume that the last part belongs to a class and the rest to the namespace containing the class
        [*class_namespace_path, class_name] = namespace_path
        parent_namespace = _create_ghidra_namespace(
            api, NamespacePath(class_namespace_path)
        )
        return api.createClass(parent_namespace, class_name)


def get_class_namespace_and_name(
    api: FlatProgramAPI, name_with_namespace: str
) -> tuple[Namespace, str]:
    """
    For a given entity inside a namespace or class (e.g. `namespace::class::fn`),
    returns the appropriate Ghidra namespace and extracts the base name as a string, e.g.
    `(Namespace("namespace::class"), "fn")`. Creates the namespaces and class if necessary.
    """
    sanitized_name = sanitize_name(name_with_namespace)
    namespace = get_or_create_class_namespace(api, sanitized_name.namespace_path)
    return namespace, sanitized_name.base_name


def set_ghidra_label(api: FlatProgramAPI, address: int, label_with_namespace: str):
    namespace, name = get_class_namespace_and_name(api, label_with_namespace)
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
