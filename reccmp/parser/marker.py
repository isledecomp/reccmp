import re
from typing import NamedTuple
from enum import Enum

TargetAliases = dict[str, str]
ProjectAliases = dict[str, TargetAliases]


class MarkerCategory(Enum):
    """For the purposes of grouping multiple different DecompMarkers together,
    assign a rough "category" for the MarkerType values below.
    It's really only the function types that have to get folded down, but
    we'll do that in a structured way to permit future expansion."""

    FUNCTION = 1
    VARIABLE = 2
    STRING = 3
    VTABLE = 4
    LINE = 5
    ADDRESS = 100  # i.e. no comparison required or possible


class MarkerType(Enum):
    UNKNOWN = -100
    FUNCTION = 1
    STUB = 2
    SYNTHETIC = 3
    TEMPLATE = 4
    GLOBAL = 5
    VTABLE = 6
    STRING = 7
    LIBRARY = 8
    LINE = 9


markerRegex = re.compile(
    r"\s*//\s*(?P<type>\w+):\s*(?P<module>\w+)\s+(?P<offset>0x[a-f0-9]+) *(?P<extra>\S.+\S)?",
    flags=re.I,
)


markerExactRegex = re.compile(
    r"\s*// (?P<type>[A-Z]+): (?P<module>[A-Z0-9]+) (?P<offset>0x[a-f0-9]+)(?: (?P<extra>\S.+\S))?\n?$"
)


MARKER_CATEGORY_MAP = {
    MarkerType.FUNCTION: MarkerCategory.FUNCTION,
    MarkerType.STUB: MarkerCategory.FUNCTION,
    MarkerType.SYNTHETIC: MarkerCategory.FUNCTION,
    MarkerType.TEMPLATE: MarkerCategory.FUNCTION,
    MarkerType.LIBRARY: MarkerCategory.FUNCTION,
    MarkerType.VTABLE: MarkerCategory.VTABLE,
    MarkerType.GLOBAL: MarkerCategory.VARIABLE,
    MarkerType.STRING: MarkerCategory.STRING,
    MarkerType.LINE: MarkerCategory.ADDRESS,
    MarkerType.UNKNOWN: MarkerCategory.ADDRESS,
}


class DecompMarker(NamedTuple):
    type: MarkerType
    module: str
    offset: int
    extra: str | None = None

    @property
    def key(self) -> tuple[MarkerCategory, str, str | None]:
        """For use with the MarkerDict. To detect/avoid marker collision."""
        return (MARKER_CATEGORY_MAP[self.type], self.module, self.extra)


def normalize_target_aliases(aliases: TargetAliases) -> TargetAliases:
    """Drop invalid aliases that meet one of these criteria:
    1. They try to overwrite a built-in marker type. e.g. FUNCTION -> GLOBAL
    2. They do not point to a built-in marker type. e.g. TEST -> HELLO
    3. They repeat a previous alias. e.g. aliases on "Func" and "func" (different case)
    """
    builtin_types = {t.name for t in MarkerType}
    allowed_pairs = []
    seen_keys = set()

    for key, value in aliases.items():
        if (
            key.upper() not in builtin_types
            and value.upper() in builtin_types
            and key.upper() not in seen_keys
        ):
            # Key name converted for lookup
            seen_keys.add(key.upper())
            allowed_pairs.append((key.upper(), value))

    return dict(allowed_pairs)


def normalize_project_aliases(project_aliases: ProjectAliases) -> ProjectAliases:
    output = {}

    for target, aliases in project_aliases.items():
        normalized = normalize_target_aliases(aliases)
        # Drop this target if there are no valid aliases left.
        if normalized:
            # Target name converted for lookup
            output[target.upper()] = normalized

    return output


def resolve_alias(marker_type: str, target_name: str, aliases: ProjectAliases) -> str:
    if not aliases or target_name.upper() not in aliases:
        return marker_type

    return aliases[target_name.upper()].get(marker_type.upper(), marker_type)


def match_marker(
    line: str, aliases: ProjectAliases | None = None
) -> DecompMarker | None:
    if aliases is None:
        aliases = {}

    match = markerRegex.match(line)
    if match is None:
        return None

    marker_type, target_name, offset_str, extra = match.groups()
    marker_type = resolve_alias(marker_type, target_name, aliases)

    try:
        enum_type = MarkerType[marker_type.upper()]
    except KeyError:
        enum_type = MarkerType.UNKNOWN

    return DecompMarker(
        type=enum_type,
        # Convert to upper here. A lot of other analysis depends on this name
        # being consistent and predictable. If the name is _not_ capitalized
        # we will emit a syntax error.
        module=target_name.upper(),
        offset=int(offset_str, 16),
        extra=extra,
    )


def is_marker_exact(line: str) -> bool:
    return markerExactRegex.match(line) is not None
