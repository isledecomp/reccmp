from typing import TypeVar

T = TypeVar("T")


def assert_instance(value: object, expected_class: type[T]) -> T:
    """Type narrowing does not work well in the IDE for some reason, this makes it explicit"""
    assert isinstance(value, expected_class)
    return value
