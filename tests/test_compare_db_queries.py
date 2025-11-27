"""Testing results of complex queries on the entity database"""

import pytest
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.compare.queries import (
    get_overloaded_functions,
)
from reccmp.isledecomp.types import EntityType, ImageId


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


def test_overloaded_functions_ignore_thunks(db: EntityDb):
    """When deciding which functions have duplicate names, exclude thunk entities."""
    with db.batch() as batch:
        # Unique among non-ref functions
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(200, name="Hello", type=EntityType.THUNK)
        batch.set_ref(ImageId.ORIG, 200, ref=1000)
        # Non-unique but both are refs
        batch.set_orig(300, name="Test", type=EntityType.THUNK)
        batch.set_orig(400, name="Test", type=EntityType.THUNK)
        batch.set_ref(ImageId.ORIG, 300, ref=1000)
        batch.set_ref(ImageId.ORIG, 400, ref=1000)
        # Non-unique but should ignore the ref function
        batch.set_orig(500, name="Hey", type=EntityType.FUNCTION)
        batch.set_orig(600, name="Hey", type=EntityType.FUNCTION)
        batch.set_orig(700, name="Hey", type=EntityType.THUNK)
        batch.set_ref(ImageId.ORIG, 700, ref=1000)

    # Should only include the duplicate names where both are not ref entities.
    overloaded = list(get_overloaded_functions(db))
    assert [func.orig_addr for func in overloaded] == [500, 600]
