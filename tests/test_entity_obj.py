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
    name = create_entity(100, 200, name="Test").match_name()
    assert name is not None
    assert "Test" in name
    assert "UNK" in name


def test_match_name_with_type():
    """Use all-caps representation of entity type in the match name"""
    name = create_entity(100, 200, type=EntityType.FUNCTION, name="Test").match_name()
    assert name is not None
    assert "Test" in name
    assert "FUNCTION" in name


def test_match_name_computed_name():
    """Use the 'computed_name' field if present"""
    name = create_entity(100, 200, computed_name="Hello").match_name()
    assert name is not None
    assert "Hello" in name


def test_match_name_priority():
    """Prefer 'computed_name' over 'name'"""
    name = create_entity(100, 200, computed_name="Hello", name="Test").match_name()
    assert name is not None
    assert "Hello" in name
