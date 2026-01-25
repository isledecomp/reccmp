import logging
from typing import Callable, Iterator, NamedTuple, TypeVar

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

# pylint: disable=too-many-return-statements # a `match` would be better, but for now we are stuck with Python 3.9
# pylint: disable=no-else-return # Not sure why this rule even is a thing, this is great for checking exhaustiveness

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.data import (
    ArrayDataType,
    CategoryPath,
    DataType,
    DataTypeConflictHandler,
    Enum,
    EnumDataType,
    StructureDataType,
    StructureInternal,
    TypedefDataType,
    ComponentOffsetSettingsDefinition,
)
from ghidra.util.task import ConsoleTaskMonitor

from reccmp.cvdump.types import (
    CvdumpParsedType,
    FieldListItem,
    VirtualBasePointer,
)

from .entity_names import NamespacePath, SanitizedEntityName, sanitize_name
from .exceptions import (
    MultipleTypesFoundInGhidraError,
    TypeNotFoundError,
    TypeNotFoundInGhidraError,
    TypeNotImplementedError,
    StructModificationError,
)
from .ghidra_helper import (
    add_data_type_or_reuse_existing,
    category_path_of,
    get_or_add_pointer_type,
    get_ghidra_type,
    get_or_create_class_namespace,
    get_scalar_ghidra_type,
)
from .pdb_extraction import PdbFunctionExtractor

logger = logging.getLogger(__name__)


class GhidraFieldListItem(NamedTuple):
    """Using a Ghidra DataType instead of the Cvdump type key from FieldListItem"""

    type: DataType
    name: str
    offset: int


class PdbTypeImporter:
    """Allows PDB types to be imported into Ghidra."""

    def __init__(
        self,
        api: FlatProgramAPI,
        extraction: PdbFunctionExtractor,
        ignore_types: set[str],
    ):
        self.api = api
        self.extraction = extraction
        self.ignore_types = ignore_types
        # tracks the structs/classes we have already started to import, otherwise we run into infinite recursion
        self.handled_structs: set[SanitizedEntityName] = set()

        # tracks the enums we have already handled for the sake of efficiency
        self.handled_enums: dict[SanitizedEntityName, Enum] = {}

    @property
    def types(self):
        return self.extraction.compare.types

    def import_pdb_type_into_ghidra(
        self, type_index: str, slim_for_vbase: bool = False
    ) -> DataType:
        """
        Recursively imports a type from the PDB into Ghidra.
        @param type_index Either a scalar type like `T_INT4(...)` or a PDB reference like `0x10ba`
        @param slim_for_vbase If true, the current invocation
            imports a superclass of some class where virtual inheritance is involved (directly or indirectly).
            This case requires special handling: Let's say we have `class C: B` and `class B: virtual A`. Then cvdump
            reports a size for B that includes both B's fields as well as the A contained at an offset within B,
            which is not the correct structure to be contained in C. Therefore, we need to create a "slim" version of B
            that fits inside C.
            This value should always be `False` when the referenced type is not (a pointer to) a class.
        """
        type_index_lower = type_index.lower()
        if type_index_lower.startswith("t_"):
            return self._import_scalar_type(type_index_lower)

        try:
            type_pdb = self.extraction.compare.types.keys[type_index_lower]
        except KeyError as e:
            raise TypeNotFoundError(
                f"Failed to find referenced type '{type_index_lower}'"
            ) from e

        type_category = type_pdb["type"]

        # follow forward reference (class, struct, union)
        if type_pdb.get("is_forward_ref", False):
            return self._import_forward_ref_type(
                type_index_lower, type_pdb, slim_for_vbase
            )

        if type_category == "LF_POINTER":
            return get_or_add_pointer_type(
                self.api,
                self.import_pdb_type_into_ghidra(
                    type_pdb["element_type"], slim_for_vbase
                ),
            )
        elif type_category in ["LF_CLASS", "LF_STRUCTURE"]:
            return self._import_class_or_struct(type_pdb, slim_for_vbase)
        elif type_category == "LF_ARRAY":
            return self._import_array(type_pdb)
        elif type_category == "LF_ENUM":
            return self._import_enum(type_pdb)
        elif type_category == "LF_PROCEDURE":
            logger.warning(
                "Not implemented: Function-valued argument or return type will be replaced by void pointer: %s",
                type_pdb,
            )
            return get_scalar_ghidra_type(self.api, "void")
        elif type_category == "LF_UNION":
            return self._import_union(type_pdb)
        else:
            raise TypeNotImplementedError(type_pdb)

    _scalar_type_map = {
        "rchar": "char",
        "int4": "int",
        "uint4": "uint",
        "real32": "float",
        "real64": "double",
    }

    def _scalar_type_to_cpp(self, scalar_type: str) -> str:
        if scalar_type.startswith("32p"):
            return f"{self._scalar_type_to_cpp(scalar_type[3:])} *"
        return self._scalar_type_map.get(scalar_type, scalar_type)

    def _import_scalar_type(self, type_index_lower: str) -> DataType:
        if (match := self.extraction.scalar_type_regex.match(type_index_lower)) is None:
            raise TypeNotFoundError(f"Type has unexpected format: {type_index_lower}")

        scalar_cpp_type = self._scalar_type_to_cpp(match.group("typename"))
        return get_scalar_ghidra_type(self.api, scalar_cpp_type)

    def _import_forward_ref_type(
        self,
        type_index,
        type_pdb: CvdumpParsedType,
        slim_for_vbase: bool = False,
    ) -> DataType:
        referenced_type = type_pdb.get("udt") or type_pdb.get("modifies")
        if referenced_type is None:
            try:
                # Example: HWND__, needs to be created manually
                raw_name: str = type_pdb["name"]
                type_name_and_namespace = sanitize_name(raw_name)
                return get_ghidra_type(self.api, type_name_and_namespace)
            except TypeNotFoundInGhidraError as e:
                raise TypeNotImplementedError(
                    f"{type_index}: forward ref without target, needs to be created manually: {type_pdb}"
                ) from e
        logger.debug(
            "Following forward reference from %s to %s",
            type_index,
            referenced_type,
        )
        return self.import_pdb_type_into_ghidra(referenced_type, slim_for_vbase)

    def _import_array(self, type_pdb: CvdumpParsedType) -> DataType:
        inner_type = self.import_pdb_type_into_ghidra(type_pdb["array_type"])

        array_total_bytes: int = type_pdb["size"]
        data_type_size = inner_type.getLength()
        array_length, modulus = divmod(array_total_bytes, data_type_size)
        assert (
            modulus == 0
        ), f"Data type size {data_type_size} does not divide array size {array_total_bytes}"

        return ArrayDataType(inner_type, array_length, 0)

    def _import_union(self, type_pdb: CvdumpParsedType) -> DataType:
        raw_name: str = type_pdb["name"]
        expected_size: int = type_pdb["size"]
        type_name_with_namespace = sanitize_name(raw_name)

        try:
            logger.debug("Dereferencing union %s", type_pdb)
            union_type = get_ghidra_type(self.api, type_name_with_namespace)
            assert (
                union_type.getLength() == expected_size
            ), f"Wrong size of existing union type '{raw_name}': expected {expected_size}, got {union_type.getLength()}"
            return union_type
        except TypeNotFoundInGhidraError as e:
            # We have so few instances, it is not worth implementing this
            raise TypeNotImplementedError(
                f"Writing union types is not supported. Please add by hand: {type_pdb}"
            ) from e

    def _import_enum(self, type_pdb: CvdumpParsedType) -> DataType:
        underlying_type = self.import_pdb_type_into_ghidra(type_pdb["underlying_type"])
        field_list = self.extraction.compare.types.keys.get(type_pdb["field_list_type"])
        assert field_list is not None, f"Failed to find field list for enum {type_pdb}"
        type_name: str = type_pdb["name"]

        result = self._get_or_create_enum_data_type(
            type_name, underlying_type.getLength()
        )
        # clear existing variant if there are any
        for existing_variant in result.getNames():
            result.remove(existing_variant)

        for variant in field_list.get("variants", []):
            result.add(variant.name, variant.value)

        return result

    def _import_class_or_struct(
        self,
        type_in_pdb: CvdumpParsedType,
        slim_for_vbase: bool = False,
    ) -> DataType:
        field_list_type: str = type_in_pdb["field_list_type"]
        field_list = self.types.keys[field_list_type.lower()]

        class_size: int = type_in_pdb["size"]
        raw_name: str = type_in_pdb["name"]
        if slim_for_vbase:
            raw_name += "_vbase_slim"
        sanitized_name = sanitize_name(raw_name)

        if sanitized_name in self.handled_structs:
            logger.debug(
                "Class has been handled or is being handled: %s",
                sanitized_name,
            )
            return get_ghidra_type(self.api, sanitized_name)

        logger.debug("--- Beginning to import class/struct '%s'", sanitized_name)

        # Add as soon as we start to avoid infinite recursion.
        # We use tuples because they are hashable
        self.handled_structs.add(sanitized_name)

        # We need a class/namespace for the class itself, not just for its parent,
        # so we need to add the base name to the second argument
        get_or_create_class_namespace(
            self.api,
            NamespacePath((*sanitized_name.namespace_path, sanitized_name.base_name)),
        )

        if raw_name in self.ignore_types:
            # Respect ignore-list
            try:
                result = get_ghidra_type(self.api, sanitized_name)
                logger.info(
                    "Skipping import of class '%s' because it is on the ignore list",
                    sanitized_name,
                )
                return result
            except TypeNotFoundInGhidraError:
                logger.warning(
                    "Importing class '%s' despite it being on the ignore list because it is not present in Ghidra.",
                    sanitized_name,
                )

        new_ghidra_struct = self._get_or_create_struct_data_type(
            sanitized_name, class_size
        )

        if (old_size := new_ghidra_struct.getLength()) != class_size:
            logger.warning(
                "Existing class %s had incorrect size %d. Setting to %d...",
                sanitized_name,
                old_size,
                class_size,
            )

        logger.info("Adding class data type %s", sanitized_name)
        logger.debug("Class information: %s", type_in_pdb)

        components: list[GhidraFieldListItem] = []
        components.extend(self._get_components_from_base_classes(field_list))
        # can be missing when no new fields are declared
        components.extend(self._get_components_from_members(field_list))
        components.extend(
            self._get_components_from_vbase(
                field_list, sanitized_name, new_ghidra_struct
            )
        )

        components.sort(key=lambda c: c.offset)

        if slim_for_vbase:
            # Make a "slim" version: shrink the size to the fields that are actually present.
            # This makes a difference when the current class uses virtual inheritance
            assert (
                len(components) > 0
            ), f"Error: {sanitized_name} should not be empty. There must be at least one direct or indirect vbase pointer."
            last_component = components[-1]
            class_size = last_component.offset + last_component.type.getLength()

        self._overwrite_struct(
            sanitized_name,
            new_ghidra_struct,
            class_size,
            components,
        )

        logger.info("Finished importing class %s", sanitized_name)

        return new_ghidra_struct

    def _get_components_from_base_classes(
        self, field_list: CvdumpParsedType
    ) -> Iterator[GhidraFieldListItem]:
        non_virtual_base_classes: dict[str, int] = field_list.get("super", {})

        for super_type, offset in non_virtual_base_classes.items():
            # If we have virtual inheritance _and_ a non-virtual base class here, we play safe and import slim version.
            # This is technically not needed if only one of the superclasses uses virtual inheritance, but I am not aware of any instance.
            import_slim_vbase_version_of_superclass = "vbase" in field_list
            ghidra_type = self.import_pdb_type_into_ghidra(
                super_type, slim_for_vbase=import_slim_vbase_version_of_superclass
            )

            yield GhidraFieldListItem(
                type=ghidra_type,
                offset=offset,
                name="base" if offset == 0 else f"base_{ghidra_type.getName()}",
            )

    def _get_components_from_members(
        self, field_list: CvdumpParsedType
    ) -> Iterator[GhidraFieldListItem]:
        members: list[FieldListItem] = field_list.get("members") or []
        for member in members:
            yield GhidraFieldListItem(
                type=self.import_pdb_type_into_ghidra(member.type),
                offset=member.offset,
                name=member.name,
            )

    def _get_components_from_vbase(
        self,
        field_list: CvdumpParsedType,
        sanitized_name: SanitizedEntityName,
        current_type: StructureInternal,
    ) -> Iterator[GhidraFieldListItem]:
        vbasepointer: VirtualBasePointer | None = field_list.get("vbase", None)

        if vbasepointer is not None and any(x.direct for x in vbasepointer.bases):
            vbaseptr_type = get_or_add_pointer_type(
                self.api,
                self._import_vbaseptr(current_type, sanitized_name, vbasepointer),
            )
            yield GhidraFieldListItem(
                type=vbaseptr_type,
                offset=vbasepointer.vboffset,
                name="vbase_offset",
            )

    def _import_vbaseptr(
        self,
        current_type: StructureInternal,
        sanitized_name: SanitizedEntityName,
        vbasepointer: VirtualBasePointer,
    ) -> StructureInternal:
        pointer_size = 4  # hard-code to 4 because of 32 bit

        components = [
            GhidraFieldListItem(
                offset=0,
                type=get_or_add_pointer_type(self.api, current_type),
                name="o_self",
            )
        ]
        for vbase in vbasepointer.bases:
            vbase_ghidra_type = self.import_pdb_type_into_ghidra(vbase.type)

            type_name = vbase_ghidra_type.getName()

            vbase_ghidra_pointer = get_or_add_pointer_type(self.api, vbase_ghidra_type)
            vbase_ghidra_pointer_typedef = TypedefDataType(
                vbase_ghidra_pointer.getCategoryPath(),
                f"{type_name}PtrOffset",
                vbase_ghidra_pointer,
            )
            # Set a default value of -4 for the pointer offset. While this appears to be correct in many cases,
            # it does not always lead to the best decompile. It can be fine-tuned by hand; the next function call
            # makes sure that we don't overwrite this value on re-running the import.
            ComponentOffsetSettingsDefinition.DEF.setValue(
                vbase_ghidra_pointer_typedef.getDefaultSettings(), -4
            )

            vbase_ghidra_pointer_typedef = add_data_type_or_reuse_existing(
                self.api, vbase_ghidra_pointer_typedef
            )

            components.append(
                GhidraFieldListItem(
                    offset=vbase.index * pointer_size,
                    type=vbase_ghidra_pointer_typedef,
                    name=f"o_{type_name}",
                )
            )

        size = len(components) * pointer_size

        # Turns e.g. `SomeNamespace::LegoAnimActor` into `SomeNamespace::LegoAnimActor::VBasePtr`
        vbase_ptr_type_name = SanitizedEntityName(
            NamespacePath((*sanitized_name.namespace_path, sanitized_name.base_name)),
            "VBasePtr",
        )

        new_ghidra_struct = self._get_or_create_struct_data_type(
            vbase_ptr_type_name, size
        )

        self._overwrite_struct(
            vbase_ptr_type_name,
            new_ghidra_struct,
            size,
            components,
        )

        return new_ghidra_struct

    def _overwrite_struct(
        self,
        sanitized_name: SanitizedEntityName,
        new_ghidra_struct: StructureInternal,
        class_size: int,
        components: list[GhidraFieldListItem],
    ):
        new_ghidra_struct.deleteAll()
        new_ghidra_struct.growStructure(class_size)

        # this case happened e.g. for IUnknown, which linked to an (incorrect) existing library, and some other types as well.
        # Unfortunately, we don't get proper error handling for read-only types.
        # However, we really do NOT want to do this every time because the type might be self-referential and partially imported.
        if new_ghidra_struct.getLength() != class_size:
            new_ghidra_struct = self._delete_and_recreate_struct_data_type(
                sanitized_name, class_size, new_ghidra_struct
            )

        for component in components:
            offset: int = component.offset
            logger.debug("Adding component %s to class: %s", component, sanitized_name)

            try:
                # Make sure there is room for the new structure and that we have no collision.
                existing_type = new_ghidra_struct.getComponentAt(offset)
                assert (
                    existing_type is not None
                ), f"Struct collision: Offset {offset} in {sanitized_name} is overlapped by another component"

                if existing_type.getDataType().getName() != "undefined":
                    # collision of structs beginning in the same place -> likely due to unions
                    logger.warning(
                        "Struct collision: Offset %d of %s already has a field (likely an inline union)",
                        offset,
                        sanitized_name,
                    )

                new_ghidra_struct.replaceAtOffset(
                    offset,
                    component.type,
                    -1,  # set to -1 for fixed-size components
                    component.name,  # name
                    None,  # comment
                )
            except Exception as e:
                raise StructModificationError(sanitized_name) from e

    def _get_or_create_enum_data_type(
        self, type_name: str, enum_type_size: int
    ) -> Enum:
        enum_type_name_with_namespace = sanitize_name(type_name)

        if (
            known_enum := self.handled_enums.get(enum_type_name_with_namespace, None)
        ) is not None:
            return known_enum

        result = self._get_or_create_data_type(
            enum_type_name_with_namespace,
            "enum",
            Enum,
            lambda categoryPath, name: EnumDataType(categoryPath, name, enum_type_size),
        )
        self.handled_enums[enum_type_name_with_namespace] = result
        return result

    def _get_or_create_struct_data_type(
        self, sanitized_name: SanitizedEntityName, class_size: int
    ) -> StructureInternal:
        return self._get_or_create_data_type(
            sanitized_name,
            "class/struct",
            StructureInternal,
            lambda category_path, class_name: StructureDataType(
                category_path, class_name, class_size
            ),
        )

    T = TypeVar("T", bound=DataType)

    def _get_or_create_data_type(
        self,
        sanitized_name: SanitizedEntityName,
        readable_name_of_type_category: str,
        expected_type: type[T],
        new_instance_callback: Callable[[CategoryPath, str], T],
    ) -> T:
        """
        Checks if a data type provided under the given name exists in Ghidra.
        Creates one using `new_instance_callback` if there is not.
        Also verifies the data type.

        Note that the return value of `addDataType()` is not the same instance as the input
        even if there is no name collision.
        """

        data_type_manager = self.api.getCurrentProgram().getDataTypeManager()
        category_path = category_path_of(sanitized_name.namespace_path)

        try:
            data_type = get_ghidra_type(self.api, sanitized_name)
            logger.debug(
                "Found existing %s type %s under category path %s",
                readable_name_of_type_category,
                sanitized_name,
                data_type.getCategoryPath(),
            )
        except TypeNotFoundInGhidraError:
            logger.info(
                "Creating new %s data type %s",
                readable_name_of_type_category,
                sanitized_name,
            )
            data_type = data_type_manager.addDataType(
                new_instance_callback(category_path, sanitized_name.base_name),
                DataTypeConflictHandler.KEEP_HANDLER,
            )
        except MultipleTypesFoundInGhidraError as e:
            logger.error(
                "Found multiple existing types matching '%s'. Deleting all of them and trying to recreate..."
            )
            for result in e.results:
                logger.info("Deleting data type '%s'", result.getPathName())
                data_type_manager.remove(result, ConsoleTaskMonitor())
            logger.info(
                "(Re)creating new %s data type '%s'",
                readable_name_of_type_category,
                sanitized_name,
            )
            data_type = data_type_manager.addDataType(
                new_instance_callback(category_path, sanitized_name.base_name),
                DataTypeConflictHandler.KEEP_HANDLER,
            )

        assert isinstance(
            data_type, expected_type
        ), f"Found existing type named {sanitized_name} that is not a {readable_name_of_type_category}"
        return data_type

    def _delete_and_recreate_struct_data_type(
        self,
        sanitized_name: SanitizedEntityName,
        class_size: int,
        existing_data_type: DataType,
    ) -> StructureInternal:
        logger.warning(
            "Failed to modify data type %s. Will try to delete the existing one and re-create the imported one.",
            sanitized_name,
        )

        category_path = category_path_of(sanitized_name.namespace_path)

        assert (
            self.api.getCurrentProgram()
            .getDataTypeManager()
            .remove(existing_data_type, ConsoleTaskMonitor())
        ), f"Failed to delete and re-create data type {sanitized_name}"
        data_type = StructureDataType(category_path, sanitized_name, class_size)
        data_type = (
            self.api.getCurrentProgram()
            .getDataTypeManager()
            .addDataType(data_type, DataTypeConflictHandler.KEEP_HANDLER)
        )
        assert isinstance(data_type, StructureInternal)  # for type checking
        return data_type
