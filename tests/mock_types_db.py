from typing import NamedTuple
from reccmp.cvdump.types import (
    ClassInfo,
    CvdumpKeyError,
    CvdumpTypeKey,
    CvdumpTypesParser,
    FieldListItem,
    TypeInfo,
    TypeKind,
)


class MockStruct(NamedTuple):
    key: CvdumpTypeKey
    size: int
    members: list[FieldListItem]


# pylint: disable=abstract-method
class MockTypesDb(CvdumpTypesParser):
    """Implements `TypesDb` with mocked structs."""

    structs: dict[CvdumpTypeKey, MockStruct]

    def __init__(self, structs: list[MockStruct]) -> None:
        super().__init__()
        self.structs = {struct.key: struct for struct in structs}

    def get(self, type_key: CvdumpTypeKey) -> TypeInfo:
        if type_key.is_scalar():
            return super().get(type_key)

        try:
            struct = self.structs[type_key]
        except KeyError as ex:
            raise CvdumpKeyError(type_key) from ex

        return TypeInfo(type_key, TypeKind.STRUCT, struct.size, None)

    def members(self, type_key: CvdumpTypeKey) -> list[FieldListItem]:
        return self.structs[type_key].members

    def base_classes(self, type_key: CvdumpTypeKey) -> dict[CvdumpTypeKey, int]:
        assert type_key in self.structs
        return {}

    def class_info(self, type_key: CvdumpTypeKey) -> ClassInfo:
        assert type_key in self.structs
        return ClassInfo(has_vftable=False, vbptr_offset=None, virtual_bases=[])
