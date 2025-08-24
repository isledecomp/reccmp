from typing import NamedTuple


NamespacePath = tuple[str, ...]


class SanitizedEntityName(NamedTuple):
    namespace_path: NamespacePath
    base_name: str

    def __str__(self):
        return "::".join(list(self.namespace_path) + [self.base_name])
