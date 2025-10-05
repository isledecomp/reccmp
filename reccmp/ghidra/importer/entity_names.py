import logging
import re
from typing import NamedTuple


class NamespacePath(tuple[str, ...]):
    def __str__(self):
        return "::".join(self)


class SanitizedEntityName(NamedTuple):
    namespace_path: NamespacePath
    base_name: str

    def __str__(self):
        return "::".join(list(self.namespace_path) + [self.base_name])


logger = logging.getLogger(__file__)


# These appear in debug builds
THUNK_OF_RE = re.compile(r"^Thunk of '(.*)'$")


def sanitize_name(name: str) -> SanitizedEntityName:
    """
    Takes a full class or function name and replaces characters not accepted by Ghidra.
    Applies mostly to templates, names like `vbase destructor`, and thunks in debug builds.

    The result consists of a namespace path and a base name, e.g.
    ```
    sanitize_name("a::b::c") ~ { namespace_path: ["a", "b"], base_name: "c" }
    ```
    """
    if (match := THUNK_OF_RE.fullmatch(name)) is not None:
        # We want `Thunk of 'namespace::function'` to turn into `namespace::_thunk_function`
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

    new_name_split = []

    # How many nested template arguments have been opened minus how many have been closed
    chevron_depth = 0

    # This logic is needed so we don't accidentally split "a<b::c>" into a namespace "a<b" and an entity "c>"
    for part in new_name.split("::"):
        if chevron_depth == 0:
            new_name_split += [part]
        else:
            # new_name_split is guaranteed to have a length >= 1 because chevron_depth is initialised to 0,
            # so the other branch of this `if-else` has been taken at least once if we got here
            new_name_split[-1] += f"::{part}"
        # chevrons have been replaced by brackets at this point
        chevron_depth += part.count("[") - part.count("]")

    if is_thunk:
        new_name_split[-1] = "_thunk_" + new_name_split[-1]

    new_name = "::".join(new_name_split)
    if new_name != name:
        logger.info(
            "Changed entity name from '%s' to '%s' to avoid Ghidra issues",
            name,
            new_name,
        )

    [*namespace_path, base_name] = new_name_split
    return SanitizedEntityName(NamespacePath(namespace_path), base_name)
