"""Tests related to the ReccmpEntity ORM object"""

import json
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.compare.db import ReccmpEntity


def create_entity(
    orig_addr: int | None, recomp_addr: int | None, **kwargs
) -> ReccmpEntity:
    """Helper to create the JSON string representation of the key/value args."""
    return ReccmpEntity(orig_addr, recomp_addr, json.dumps(kwargs))


def test_match_name_none():
    """match_name() returns None if there are no name attributes"""
    assert create_entity(100, 200).match_name() is None


def test_match_name_no_type():
    """If we have a name, the entity_type is included in the match_name().
    If type is None, the type string is 'UNK'"""
    e = create_entity(100, 200, name="Test")
    assert "Test" in e.match_name()
    assert "UNK" in e.match_name()


def test_match_name_with_type():
    """Use all-caps representation of entity type in the match name"""
    e = create_entity(100, 200, type=EntityType.FUNCTION, name="Test")
    assert "Test" in e.match_name()
    assert "FUNCTION" in e.match_name()


def test_match_name_computed_name():
    """Use the 'computed_name' field if present"""
    e = create_entity(100, 200, computed_name="Hello")
    assert "Hello" in e.match_name()


def test_match_name_priority():
    """Prefer 'computed_name' over 'name'"""
    e = create_entity(100, 200, computed_name="Hello", name="Test")
    assert "Hello" in e.match_name()


def test_computed_name_string():
    """Ignore 'computed_name' if entity is a string"""

    e = create_entity(
        100, 200, computed_name="Hello", name="Test", type=EntityType.STRING
    )
    assert "Test" in e.match_name()


def test_match_name_string():
    """We currently store the string value in the name field.
    If the string includes newlines, we need to escape them before replacing the
    value during asm sanitize. (It will interfere with diff calculation.)"""
    string = """A string
    with
    newlines"""

    e = create_entity(100, None, type=EntityType.STRING, name=string)
    assert "\n" not in e.match_name()
    assert "\\n" in e.match_name()
