"""Tests for the `match_array_elements` function from the reccmp compare.
For matched variable array entities, create and match new entities for each array element.
"""

import pytest
from reccmp.compare.mutate import (
    match_array_elements,
)
from reccmp.types import EntityType
from reccmp.compare.db import EntityDb
from reccmp.cvdump.types import CvdumpTypesParser, FieldListItem, CVInfoTypeEnum


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
    types_db.keys[0x1000] = {
        "type": "LF_ARRAY",
        "array_type": CVInfoTypeEnum.T_REAL32,
        "size": 8,
    }

    with db.batch() as batch:
        # NOTE: It does not work if entity size is not set.
        # We should be able to set it because how else would we have the type key?
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type=0x1000, size=8
        )
        batch.match(100, 100)

    match_array_elements(db, types_db)

    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == "test[0]"
    assert e.get("type") == EntityType.DATA
    assert e.get("size") == 8

    e = db.get_by_orig(104)
    assert e is not None
    assert e.name == "test[1]"
    assert e.get("type") == EntityType.OFFSET
    assert e.get("size") == 4
    assert e.recomp_addr == 104  # Should create new match

    e = db.get_by_recomp(100)
    assert e is not None
    assert e.name == "test[0]"
    assert e.get("type") == EntityType.DATA
    assert e.get("size") == 8

    e = db.get_by_recomp(104)
    assert e is not None
    assert e.name == "test[1]"
    assert e.get("type") == EntityType.OFFSET
    assert e.get("size") == 4
    assert e.orig_addr == 104  # Should create new match


def test_match_array_key_unset(db: EntityDb):
    """Should have no effect if the data_type key is not in the types database."""
    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type=0x1000, size=8
        )
        batch.match(100, 100)

    # Empty types db so the key lookup will fail
    match_array_elements(db, CvdumpTypesParser())

    # Does not rename main entity
    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == "test"
    assert e.get("type") == EntityType.DATA

    e = db.get_by_recomp(100)
    assert e is not None
    assert e.name == "test"
    assert e.get("type") == EntityType.DATA

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
            data_type=CVInfoTypeEnum.T_REAL32,
            size=8,
        )
        batch.match(100, 100)

    # Scalars are not currently part of the type database dict, so use an empty one.
    match_array_elements(db, CvdumpTypesParser())

    # Does not rename main entity
    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == "test"
    assert e.get("type") == EntityType.DATA

    e = db.get_by_recomp(100)
    assert e is not None
    assert e.name == "test"
    assert e.get("type") == EntityType.DATA

    # Does not create new entity
    assert db.get_by_orig(104) is None
    assert db.get_by_recomp(104) is None


def test_match_array_type_is_struct(db: EntityDb, types_db: CvdumpTypesParser):
    """Should have no effect if the data_type key is not an array.
    We do not currently populate entities for struct members."""
    types_db.keys[0x1000] = {
        "type": "LF_STRUCTURE",
        "field_list_type": 0x1001,
        "size": 8,
    }
    types_db.keys[0x1001] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="hello", type=CVInfoTypeEnum.T_REAL32),
            FieldListItem(offset=4, name="world", type=CVInfoTypeEnum.T_REAL32),
        ],
    }

    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type=0x1000, size=8
        )
        batch.match(100, 100)

    # Empty types db so the key lookup will fail
    match_array_elements(db, CvdumpTypesParser())

    # Does not rename main entity
    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == "test"
    assert e.get("type") == EntityType.DATA

    e = db.get_by_recomp(100)
    assert e is not None
    assert e.name == "test"
    assert e.get("type") == EntityType.DATA

    # Does not create new entity
    assert db.get_by_orig(104) is None
    assert db.get_by_recomp(104) is None


def test_match_array_type_orig_smaller(db: EntityDb, types_db: CvdumpTypesParser):
    """Should not create entities on the orig side if the array is known to be smaller.
    (i.e. if another DATA entity is in the way.)"""
    types_db.keys[0x1000] = {
        "type": "LF_ARRAY",
        "array_type": CVInfoTypeEnum.T_REAL32,
        "size": 8,
    }

    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type=0x1000, size=8
        )
        batch.set_orig(104, name="blocker", type=EntityType.DATA)
        batch.match(100, 100)

    match_array_elements(db, types_db)

    # Should rename first orig entity
    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == "test[0]"
    assert e.get("type") == EntityType.DATA

    # But not the second
    e = db.get_by_orig(104)
    assert e is not None
    assert e.name == "blocker"
    assert e.recomp_addr is None  # Should NOT create new match

    e = db.get_by_recomp(100)
    assert e is not None
    assert e.name == "test[0]"
    assert e.get("type") == EntityType.DATA

    e = db.get_by_recomp(104)
    assert e is not None
    assert e.name == "test[1]"
    assert e.get("type") == EntityType.OFFSET
    assert e.orig_addr is None  # Should NOT create new match


def test_match_array_array_of_structs(db: EntityDb, types_db: CvdumpTypesParser):
    """If the type is an array of structs, create entities for one level of struct members."""
    types_db.keys[0x1000] = {
        "type": "LF_ARRAY",
        "array_type": 0x1001,
        "size": 16,
    }
    types_db.keys[0x1001] = {
        "type": "LF_STRUCTURE",
        "field_list_type": 0x1002,
        "size": 8,
    }
    types_db.keys[0x1002] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="hello", type=CVInfoTypeEnum.T_REAL32),
            FieldListItem(offset=4, name="world", type=CVInfoTypeEnum.T_REAL32),
        ],
    }

    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type=0x1000, size=16
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

    # Should create offset entities but not alter the parent variable entity.
    orig_types = [e.get("type") for e in orig_entities if e]
    orig_sizes = [e.get("size") for e in orig_entities if e]
    assert orig_types == [
        EntityType.DATA,
        EntityType.OFFSET,
        EntityType.OFFSET,
        EntityType.OFFSET,
    ]
    assert orig_sizes == [16, 4, 4, 4]

    recomp_types = [e.get("type") for e in recomp_entities if e]
    recomp_sizes = [e.get("size") for e in recomp_entities if e]
    assert recomp_types == [
        EntityType.DATA,
        EntityType.OFFSET,
        EntityType.OFFSET,
        EntityType.OFFSET,
    ]
    assert recomp_sizes == [16, 4, 4, 4]


def test_match_array_array_of_arrays(db: EntityDb, types_db: CvdumpTypesParser):
    """For a multi-dimensional array, create entities for one level."""
    types_db.keys[0x1000] = {
        "type": "LF_ARRAY",
        "array_type": 0x1001,
        "size": 16,
    }
    types_db.keys[0x1001] = {
        "type": "LF_ARRAY",
        "array_type": CVInfoTypeEnum.T_REAL32,
        "size": 8,
    }

    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type=0x1000, size=16
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

    # Should create offset entities but not alter the parent variable entity.
    orig_types = [e.get("type") for e in orig_entities if e]
    orig_sizes = [e.get("size") for e in orig_entities if e]
    assert orig_types == [
        EntityType.DATA,
        EntityType.OFFSET,
        EntityType.OFFSET,
        EntityType.OFFSET,
    ]
    assert orig_sizes == [16, 4, 4, 4]

    recomp_types = [e.get("type") for e in recomp_entities if e]
    recomp_sizes = [e.get("size") for e in recomp_entities if e]
    assert recomp_types == [
        EntityType.DATA,
        EntityType.OFFSET,
        EntityType.OFFSET,
        EntityType.OFFSET,
    ]
    assert recomp_sizes == [16, 4, 4, 4]


def test_match_array_array_of_structs_limit(db: EntityDb, types_db: CvdumpTypesParser):
    """Does not create entities for offsets more than one level beyond the main entity."""
    types_db.keys[0x1000] = {
        "type": "LF_ARRAY",
        "array_type": 0x1001,
        "size": 16,
    }
    types_db.keys[0x1001] = {
        "type": "LF_STRUCTURE",
        "field_list_type": 0x1002,
        "size": 8,
    }
    types_db.keys[0x1002] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="hello", type=0x1003),
            FieldListItem(offset=4, name="world", type=0x1003),
        ],
    }
    types_db.keys[0x1003] = {
        "type": "LF_STRUCTURE",
        "field_list_type": 0x1004,
        "size": 4,
    }
    types_db.keys[0x1004] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="x", type=CVInfoTypeEnum.T_SHORT),
            FieldListItem(offset=2, name="y", type=CVInfoTypeEnum.T_SHORT),
        ],
    }

    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type=0x1000, size=16
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

    # Should create offset entities but not alter the parent variable entity.
    orig_types = [e.get("type") for e in orig_entities if e]
    orig_sizes = [e.get("size") for e in orig_entities if e]
    assert orig_types == [
        EntityType.DATA,
        EntityType.OFFSET,
        EntityType.OFFSET,
        EntityType.OFFSET,
    ]
    assert orig_sizes == [16, 4, 4, 4]

    recomp_types = [e.get("type") for e in recomp_entities if e]
    recomp_sizes = [e.get("size") for e in recomp_entities if e]
    assert recomp_types == [
        EntityType.DATA,
        EntityType.OFFSET,
        EntityType.OFFSET,
        EntityType.OFFSET,
    ]
    assert recomp_sizes == [16, 4, 4, 4]


def test_match_array_array_of_union_structs(db: EntityDb, types_db: CvdumpTypesParser):
    """GH issue #289. Demonstrating the following behavior:
    - We use the name from the first option in the union
    - We create offset entities for unions, as with a struct or multidimensional array
    - We will not create entities deeper than the second level (in this case, array -> union)
    """
    types_db.keys[0x1000] = {
        "type": "LF_ARRAY",
        "array_type": 0x1001,
        "size": 8,
    }
    types_db.keys[0x1001] = {
        "type": "LF_UNION",
        "field_list_type": 0x1002,
        "size": 4,
    }
    types_db.keys[0x1002] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="hello", type=0x1003),
            FieldListItem(offset=0, name="world", type=0x1003),
        ],
    }
    # These values will not be accessed because we do not completely flatten the structure.
    # But they are here to provide a complete example of type data.
    types_db.keys[0x1003] = {
        "type": "LF_STRUCTURE",
        "field_list_type": 0x1004,
        "size": 4,
    }
    types_db.keys[0x1004] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="a", type=CVInfoTypeEnum.T_CHAR),
            FieldListItem(offset=1, name="b", type=CVInfoTypeEnum.T_CHAR),
            FieldListItem(offset=2, name="c", type=CVInfoTypeEnum.T_CHAR),
            FieldListItem(offset=3, name="d", type=CVInfoTypeEnum.T_CHAR),
        ],
    }

    with db.batch() as batch:
        batch.set_recomp(
            100, name="test", type=EntityType.DATA, data_type=0x1000, size=8
        )
        batch.match(100, 100)

    match_array_elements(db, types_db)

    e = db.get_by_orig(100)
    assert e is not None
    assert e.name == "test[0].hello"
    assert e.get("type") == EntityType.DATA
    assert e.get("size") == 8

    e = db.get_by_orig(104)
    assert e is not None
    assert e.name == "test[1].hello"
    assert e.get("type") == EntityType.OFFSET
    assert e.get("size") == 4

    e = db.get_by_recomp(100)
    assert e is not None
    assert e.name == "test[0].hello"
    assert e.get("type") == EntityType.DATA
    assert e.get("size") == 8

    e = db.get_by_recomp(104)
    assert e is not None
    assert e.name == "test[1].hello"
    assert e.get("type") == EntityType.OFFSET
    assert e.get("size") == 4

    # Should NOT create entities for the union offsets
    assert not any(db.get_by_orig(addr) for addr in (101, 102, 103, 105, 106, 107))
    assert not any(db.get_by_recomp(addr) for addr in (101, 102, 103, 105, 106, 107))
