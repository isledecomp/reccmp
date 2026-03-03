from pathlib import Path
from typing import Annotated, Any
from pydantic import BeforeValidator, PlainSerializer
from pydantic_core import PydanticUseDefault


def coerce_sequence(value: Any) -> tuple[Any, ...]:
    """Return a tuple of values for any 1-to-n input values."""
    if value is None:
        raise PydanticUseDefault

    if isinstance(value, str):
        return (value,)

    return tuple(value)


def reduce_sequence(values: tuple[Any, ...]) -> Any:
    """Unwrap the tuple if it contains only a single value."""
    if len(values) == 1:
        return values[0]

    return values


PathSequence = Annotated[
    tuple[Path, ...],
    BeforeValidator(coerce_sequence),
    PlainSerializer(reduce_sequence),
    """Deserializes a single Path (string) or many Paths (array)
    into a tuple of Path objects. When serializing, if the list
    has only one value, unwrap to a string.""",
]
