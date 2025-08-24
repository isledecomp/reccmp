import logging
import re
from typing import NamedTuple


NamespacePath = tuple[str, ...]


class SanitizedEntityName(NamedTuple):
    namespace_path: NamespacePath
    base_name: str

    def __str__(self):
        return "::".join(list(self.namespace_path) + [self.base_name])


logger = logging.getLogger(__file__)


# These appear in debug builds
THUNK_OF_RE = re.compile(r"^Thunk of '(.*)'$")


def sanitize_name(
    name: str, name_replacements: list[tuple[str, str]] | None = None
) -> SanitizedEntityName:
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

    # Configurable replacement for names. Example use case:
    # - There is a shared code base for multiple binaries
    # - The functions in the recomp have placeholder names FUN_12345678
    # - The address in the function name matches only one of the binaries
    #
    # In that case one might want to rename the function while importing into another binary in order to tell
    # the function apart from Ghidra's auto-detected functions that have an auto-generated name of the same pattern.

    if name_replacements is not None:
        for pattern, replacement in name_replacements:
            new_name = re.sub(pattern, replacement, new_name)

    # FIXME: Make configurable for BETA10
    # if GLOBALS.target_name.upper() == "BETA10.DLL":
    #     new_name = re.sub(r"FUN_([0-9a-f]{8})", r"LEGO1_\1", new_name)

    # TODO: This is not correct for templates of the form a<b::c>
    # TODO: Unit tests for this function (split off if needed)

    new_name_split = []

    # How many nested template arguments have opened minus how many have closed
    chevron_depth = 0

    # This logic is needed so we don't accidentally split "a<b::c>" into a namespace "a<b" and an entity "c>"
    for part in new_name.split("::"):
        if chevron_depth == 0:
            new_name_split += [part]
        else:
            # new_name_split is guaranteed to have a length >= 1 because chevron_depth is initialised to 0
            new_name_split[-1] += f"::{part}"
        chevron_depth += part.count("[") - part.count("]")

    if is_thunk:
        new_name_split[-1] = "_thunk_" + new_name_split[-1]

    new_name = "::".join(new_name_split)
    if new_name != name:
        logger.info(
            "Changed class or function name from '%s' to '%s' to avoid Ghidra issues",
            name,
            new_name,
        )

    [*namespace_path, base_name] = new_name_split
    return SanitizedEntityName(tuple(namespace_path), base_name)
