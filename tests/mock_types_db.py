from reccmp.cvdump.types import (
    CvdumpTypeKey,
    CvdumpTypesParser,
    TypeInfo,
)


# pylint: disable=abstract-method
class MockTypesDb(CvdumpTypesParser):
    """TypesDb with substitute return values for get().
    Other methods like get_scalars() depend on get(), so this allows
    you to easily mock complex types. The alternatives are:
    1. Reading simulated cvdump text.
    2. Create CvdumpParsedType dicts directly.
    """

    type_info: dict[CvdumpTypeKey, TypeInfo]

    def __init__(self, type_info: list[TypeInfo]) -> None:
        super().__init__()
        self.type_info = {}

        for info in type_info:
            self.type_info[info.key] = info

    def get(self, type_key: CvdumpTypeKey) -> TypeInfo:
        if type_key in self.type_info:
            return self.type_info[type_key]

        return super().get(type_key)
