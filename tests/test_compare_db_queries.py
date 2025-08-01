"""Testing results of complex queries on the entity database"""

import pytest
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.compare.queries import (
    get_overloaded_functions,
    get_named_thunks,
)
from reccmp.isledecomp.types import EntityType


@pytest.fixture(name="db")
def fixture_db():
    return EntityDb()


def test_overloaded_functions_all_unique(db: EntityDb):
    # Should start with nothing
    assert len(list(get_overloaded_functions(db))) == 0

    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(200, name="Test", type=EntityType.FUNCTION)
        batch.set_recomp(300, name="xyz", type=EntityType.FUNCTION)

    # All entities are functions, but their names are unique.
    assert len(list(get_overloaded_functions(db))) == 0


def test_overloaded_functions_ignore_non_functions(db: EntityDb):
    with db.batch() as batch:
        batch.set_orig(100, name="Hello")
        batch.set_orig(200, name="Hello")
        batch.set_recomp(300, name="Hello")

    # Name reused, but no entities are functions.
    assert len(list(get_overloaded_functions(db))) == 0

    with db.batch() as batch:
        batch.set_orig(400, name="Hello", type=EntityType.FUNCTION)

    # The name is not shared with *other* functions
    assert len(list(get_overloaded_functions(db))) == 0

    with db.batch() as batch:
        batch.set_recomp(400, name="Hello", type=EntityType.FUNCTION)

    # Now we have two entities that are functions and have the same name.
    # Don't count the other entities that are *not* functions.
    assert [func.nth for func in get_overloaded_functions(db)] == [1, 2]


def test_overloaded_functions(db: EntityDb):
    with db.batch() as batch:
        # Inserted in reverse order to test numbering
        batch.set_recomp(300, name="Hello", type=EntityType.FUNCTION)
        batch.set_recomp(200, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.match(200, 200)

    # Should have three entities, one matched, all functions and all with the name "Hello".
    overloaded = list(get_overloaded_functions(db))
    assert [func.nth for func in overloaded] == [1, 2, 3]
    assert [func.orig_addr for func in overloaded] == [100, 200, None]
    assert [func.recomp_addr for func in overloaded] == [None, 200, 300]


def test_overloaded_functions_ignore_ref(db: EntityDb):
    """Should not include functions with ref attribute set."""
    with db.batch() as batch:
        # Unique among non-ref functions
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(200, name="Hello", type=EntityType.FUNCTION, ref_orig=1000)
        # Non-unique but both are refs
        batch.set_orig(300, name="Test", type=EntityType.FUNCTION, ref_orig=1000)
        batch.set_orig(400, name="Test", type=EntityType.FUNCTION, ref_orig=1000)
        # Non-unique but should ignore the ref function
        batch.set_orig(500, name="Hey", type=EntityType.FUNCTION)
        batch.set_orig(600, name="Hey", type=EntityType.FUNCTION)
        batch.set_orig(700, name="Hey", type=EntityType.FUNCTION, ref_orig=1000)

    # Should only include the duplicate names where both are not ref entities.
    overloaded = list(get_overloaded_functions(db))
    assert [func.orig_addr for func in overloaded] == [500, 600]


def test_named_thunks_unmatched(db: EntityDb):
    """Should follow the ref_orig or ref_recomp attribute back to the
    parent entity to derive the thunk name."""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(200, ref_orig=100)
        batch.set_recomp(500, name="Test", type=EntityType.FUNCTION)
        batch.set_recomp(600, ref_recomp=500)

    names = list(get_named_thunks(db))
    assert len(names) == 2
    assert names[0].orig_addr == 200
    assert names[0].name == "Hello"
    assert names[1].recomp_addr == 600
    assert names[1].name == "Test"


def test_named_thunks_matched(db: EntityDb):
    """If the thunk has been matched to a parent matched entity
    we should get only one name reference"""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(200, ref_orig=100)
        batch.set_recomp(500, name="Test", type=EntityType.FUNCTION)
        batch.set_recomp(600, ref_recomp=500)
        # Both entity and thunk matched
        batch.match(100, 500)
        batch.match(200, 600)

    names = list(get_named_thunks(db))
    assert len(names) == 1
    assert names[0].name == "Test"  # Prefer recomp value


def test_named_thunks_no_name(db: EntityDb):
    """Do not return a name unless the parent entity has one."""
    with db.batch() as batch:
        batch.set_orig(100, type=EntityType.FUNCTION)
        batch.set_orig(200, ref_orig=100)
        batch.set_recomp(500, type=EntityType.FUNCTION)
        batch.set_recomp(600, ref_recomp=500)

    names = list(get_named_thunks(db))
    assert len(names) == 0


def test_named_thunks_prefer_computed_name(db: EntityDb):
    """Should use the computed (unique) name on the parent entity."""
    with db.batch() as batch:
        # Entity with computed name only
        batch.set_orig(100, computed_name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(200, ref_orig=100)
        # Entity with both name fields
        batch.set_recomp(500, name="X", computed_name="Test", type=EntityType.FUNCTION)
        batch.set_recomp(600, ref_recomp=500)

    names = list(get_named_thunks(db))
    assert len(names) == 2
    assert names[0].name == "Hello"
    assert names[1].name == "Test"


def test_named_thunks_crossed_ref_attr(db: EntityDb):
    """Don't use ref_recomp on an entity with only an orig_addr.
    The same is true for ref_orig on an entity with only a recomp_addr.
    This will technically still work but it probably indicates a bug."""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(200, ref_recomp=500)
        batch.set_recomp(500, name="Test", type=EntityType.FUNCTION)
        batch.set_recomp(600, ref_orig=100)

    names = list(get_named_thunks(db))
    assert len(names) == 0


def test_named_thunks_crossed_same_addr(db: EntityDb):
    """The same should be true even if the address values are the same
    in both virtual address spaces."""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(200, ref_recomp=100)
        batch.set_recomp(100, name="Test", type=EntityType.FUNCTION)
        batch.set_recomp(200, ref_orig=100)

    names = list(get_named_thunks(db))
    assert len(names) == 0


def test_named_thunks_ignore_incomplete_ref(db: EntityDb):
    """If the thunk has both ref_orig and ref_recomp but they each
    point to different entities, do not return a name."""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(200, ref_orig=100)
        batch.set_recomp(500, name="Test", type=EntityType.FUNCTION)
        batch.set_recomp(600, ref_recomp=500)
        # Only thunk is matched
        batch.match(200, 600)

    names = list(get_named_thunks(db))
    assert len(names) == 0


def test_named_thunks_ignore_incomplete_if_matched(db: EntityDb):
    """If ref_orig and ref_recomp don't point at the same entity
    don't return a name even if each parent entity is separately matched.
    i.e. don't check only that the parents are matched. They must be
    matched to each other."""
    with db.batch() as batch:
        # Establish two matched entities
        batch.set_recomp(2001, name="Hello", type=EntityType.FUNCTION)
        batch.set_recomp(2002, name="Test", type=EntityType.FUNCTION)
        batch.match(1001, 2001)
        batch.match(1002, 2002)

        # Thunk entity with ref_orig and ref_recomp that point
        # to two different matched entities.
        batch.set_orig(100, ref_orig=1001)
        batch.set_recomp(200, ref_recomp=2002)
        batch.match(100, 200)

    names = list(get_named_thunks(db))
    assert len(names) == 0
