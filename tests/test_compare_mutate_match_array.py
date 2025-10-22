"""Tests for the `match_array_elements` function from the reccmp compare.
For matched variable array entities, create and match new entities for each array element.
"""

import pytest
from reccmp.isledecomp.compare.mutate import (
    match_array_elements,
)
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.cvdump.types import CvdumpTypesParser, FieldListItem


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


@pytest.fixture(name="types_db")
def fixture_types() -> CvdumpTypesParser:
    return CvdumpTypesParser()


def test_match_array_with_nothing():
    """Should not fail if there is nothing in either database."""
    match_array_elements(EntityDb(), CvdumpTypesParser())


def test_match_array(db: EntityDb, types_db: CvdumpTypesParser):
    """Should rename the entity for the array and create a new entity for the second member."""
    types_db.keys["0x1000"] = {
        "type": "LF_ARRAY",
        "array_type": "T_REAL32",
        "size": 8,
    }

    with db.batch() as batch:
        # NOTE: It does not work if entity size is not set.
        # We should be able to set it because how else would we have the type key?
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type="0x1000", size=8
        )
        batch.match(100, 100)

    match_array_elements(db, types_db)

    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == "test[0]"

    e = db.get_by_orig(104)
    assert e is not None
    assert e.name == "test[1]"
    assert e.recomp_addr == 104  # Should create new match

    e = db.get_by_recomp(100)
    assert e is not None
    assert e.name == "test[0]"

    e = db.get_by_recomp(104)
    assert e is not None
    assert e.name == "test[1]"
    assert e.orig_addr == 104  # Should create new match


def test_match_array_key_unset(db: EntityDb):
    """Should have no effect if the data_type key is not in the types database."""
    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type="0x1000", size=8
        )
        batch.match(100, 100)

    # Empty types db so the key lookup will fail
    match_array_elements(db, CvdumpTypesParser())

    # Does not rename main entity
    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == "test"

    e = db.get_by_recomp(100)
    assert e is not None
    assert e.name == "test"

    # Does not create new entity
    assert db.get_by_orig(104) is None
    assert db.get_by_recomp(104) is None


def test_match_array_type_is_scalar(db: EntityDb):
    """Should have no effect if the data_type key is a scalar.
    TODO: The expectation will change slightly when the type database does. #211"""
    with db.batch() as batch:
        batch.set_recomp(
            100,
            name="test",
            type=EntityType.DATA,
            data_type="T_REAL32(0040)",
            size=8,
        )
        batch.match(100, 100)

    # Scalars are not currently part of the type database dict, so use an empty one.
    match_array_elements(db, CvdumpTypesParser())

    # Does not rename main entity
    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == "test"

    e = db.get_by_recomp(100)
    assert e is not None
    assert e.name == "test"

    # Does not create new entity
    assert db.get_by_orig(104) is None
    assert db.get_by_recomp(104) is None


def test_match_array_type_is_struct(db: EntityDb, types_db: CvdumpTypesParser):
    """Should have no effect if the data_type key is not an array.
    We do not currently populate entities for struct members."""
    types_db.keys["0x1000"] = {
        "type": "LF_STRUCTURE",
        "field_list_type": "0x1001",
        "size": 8,
    }
    types_db.keys["0x1001"] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="hello", type="T_REAL32"),
            FieldListItem(offset=4, name="world", type="T_REAL32"),
        ],
    }

    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type="0x1000", size=8
        )
        batch.match(100, 100)

    # Empty types db so the key lookup will fail
    match_array_elements(db, CvdumpTypesParser())

    # Does not rename main entity
    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == "test"

    e = db.get_by_recomp(100)
    assert e is not None
    assert e.name == "test"

    # Does not create new entity
    assert db.get_by_orig(104) is None
    assert db.get_by_recomp(104) is None


def test_match_array_type_orig_smaller(db: EntityDb, types_db: CvdumpTypesParser):
    """Should not create entities on the orig side if the array is known to be smaller.
    (i.e. if another DATA entity is in the way.)"""
    types_db.keys["0x1000"] = {
        "type": "LF_ARRAY",
        "array_type": "T_REAL32",
        "size": 8,
    }

    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type="0x1000", size=8
        )
        batch.set_orig(104, name="blocker", type=EntityType.DATA)
        batch.match(100, 100)

    match_array_elements(db, types_db)

    # Should rename first orig entity
    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == "test[0]"

    # But not the second
    e = db.get_by_orig(104)
    assert e is not None
    assert e.name == "blocker"
    assert e.recomp_addr is None  # Should NOT create new match

    e = db.get_by_recomp(100)
    assert e is not None
    assert e.name == "test[0]"

    e = db.get_by_recomp(104)
    assert e is not None
    assert e.name == "test[1]"
    assert e.orig_addr is None  # Should NOT create new match


def test_match_array_array_of_structs(db: EntityDb, types_db: CvdumpTypesParser):
    """If the type is an array of structs, create entities for one level of struct members."""
    types_db.keys["0x1000"] = {
        "type": "LF_ARRAY",
        "array_type": "0x1001",
        "size": 16,
    }
    types_db.keys["0x1001"] = {
        "type": "LF_STRUCTURE",
        "field_list_type": "0x1002",
        "size": 8,
    }
    types_db.keys["0x1002"] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="hello", type="T_REAL32"),
            FieldListItem(offset=4, name="world", type="T_REAL32"),
        ],
    }

    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type="0x1000", size=16
        )
        batch.match(100, 100)

    match_array_elements(db, types_db)

    orig_entities = [db.get_by_orig(addr) for addr in (100, 104, 108, 112)]
    recomp_entities = [db.get_by_recomp(addr) for addr in (100, 104, 108, 112)]

    assert all(orig_entities)
    assert all(recomp_entities)

    # "if e" required for type narrowing. mypy does not recognize the all() asserts.
    assert [e.recomp_addr for e in orig_entities if e] == [100, 104, 108, 112]
    assert [e.orig_addr for e in recomp_entities if e] == [100, 104, 108, 112]

    assert [e.name for e in orig_entities if e] == [
        "test[0].hello",
        "test[0].world",
        "test[1].hello",
        "test[1].world",
    ]
    assert [e.name for e in recomp_entities if e] == [
        "test[0].hello",
        "test[0].world",
        "test[1].hello",
        "test[1].world",
    ]


def test_match_array_array_of_arrays(db: EntityDb, types_db: CvdumpTypesParser):
    """For a multi-dimensional array, create entities for one level."""
    types_db.keys["0x1000"] = {
        "type": "LF_ARRAY",
        "array_type": "0x1001",
        "size": 16,
    }
    types_db.keys["0x1001"] = {
        "type": "LF_ARRAY",
        "array_type": "T_REAL32",
        "size": 8,
    }

    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type="0x1000", size=16
        )
        batch.match(100, 100)

    match_array_elements(db, types_db)

    orig_entities = [db.get_by_orig(addr) for addr in (100, 104, 108, 112)]
    recomp_entities = [db.get_by_recomp(addr) for addr in (100, 104, 108, 112)]

    assert all(orig_entities)
    assert all(recomp_entities)

    assert [e.recomp_addr for e in orig_entities if e] == [100, 104, 108, 112]
    assert [e.orig_addr for e in recomp_entities if e] == [100, 104, 108, 112]

    assert [e.name for e in orig_entities if e] == [
        "test[0].[0]",
        "test[0].[1]",
        "test[1].[0]",
        "test[1].[1]",
    ]
    assert [e.name for e in recomp_entities if e] == [
        "test[0].[0]",
        "test[0].[1]",
        "test[1].[0]",
        "test[1].[1]",
    ]


def test_match_array_array_of_structs_limit(db: EntityDb, types_db: CvdumpTypesParser):
    """Does not create entities for offsets more than one level beyond the main entity."""
    types_db.keys["0x1000"] = {
        "type": "LF_ARRAY",
        "array_type": "0x1001",
        "size": 16,
    }
    types_db.keys["0x1001"] = {
        "type": "LF_STRUCTURE",
        "field_list_type": "0x1002",
        "size": 8,
    }
    types_db.keys["0x1002"] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="hello", type="0x1003"),
            FieldListItem(offset=4, name="world", type="0x1003"),
        ],
    }
    types_db.keys["0x1003"] = {
        "type": "LF_STRUCTURE",
        "field_list_type": "0x1004",
        "size": 4,
    }
    types_db.keys["0x1004"] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="x", type="T_SHORT"),
            FieldListItem(offset=2, name="y", type="T_SHORT"),
        ],
    }

    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type="0x1000", size=16
        )
        batch.match(100, 100)

    match_array_elements(db, types_db)

    # Create first and second level entities. (Same as test_match_array_array_of_structs)
    orig_entities = [db.get_by_orig(addr) for addr in (100, 104, 108, 112)]
    recomp_entities = [db.get_by_recomp(addr) for addr in (100, 104, 108, 112)]

    assert all(orig_entities)
    assert all(recomp_entities)

    assert [e.recomp_addr for e in orig_entities if e] == [100, 104, 108, 112]
    assert [e.orig_addr for e in recomp_entities if e] == [100, 104, 108, 112]

    # Should not use ".x" name
    assert [e.name for e in orig_entities if e] == [
        "test[0].hello",
        "test[0].world",
        "test[1].hello",
        "test[1].world",
    ]
    assert [e.name for e in recomp_entities if e] == [
        "test[0].hello",
        "test[0].world",
        "test[1].hello",
        "test[1].world",
    ]

    # Should NOT create the third level entities. (e.g "test[0].hello.y")
    assert not any(db.get_by_orig(addr) for addr in (102, 106, 110, 114))
    assert not any(db.get_by_recomp(addr) for addr in (102, 106, 110, 114))
