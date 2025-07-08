"""Testing results of complex queries on the entity database"""

import pytest
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.compare.queries import get_overloaded_functions
from reccmp.isledecomp.types import EntityType


@pytest.fixture(name="db")
def fixture_db():
    return EntityDb()


def test_overloaded_functions_all_unique(db: EntityDb):
    # Should start with nothing
    assert len([*get_overloaded_functions(db)]) == 0

    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(200, name="Test", type=EntityType.FUNCTION)
        batch.set_recomp(300, name="xyz", type=EntityType.FUNCTION)

    # All entities are functions, but their names are unique.
    assert len([*get_overloaded_functions(db)]) == 0


def test_overloaded_functions_ignore_non_functions(db: EntityDb):
    with db.batch() as batch:
        batch.set_orig(100, name="Hello")
        batch.set_orig(200, name="Hello")
        batch.set_recomp(300, name="Hello")

    # Name reused, but no entities are functions.
    assert len([*get_overloaded_functions(db)]) == 0

    with db.batch() as batch:
        batch.set_orig(400, name="Hello", type=EntityType.FUNCTION)

    # The name is not shared with *other* functions
    assert len([*get_overloaded_functions(db)]) == 0

    with db.batch() as batch:
        batch.set_recomp(400, name="Hello", type=EntityType.FUNCTION)

    # Now we have two entities that are functions and have the same name.
    # Don't count the other entities that are *not* functions.
    assert [func.sequence for func in get_overloaded_functions(db)] == [1, 2]


def test_overloaded_functions(db: EntityDb):
    with db.batch() as batch:
        # Inserted in reverse order to test sequence numbering
        batch.set_recomp(300, name="Hello", type=EntityType.FUNCTION)
        batch.set_recomp(200, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.match(200, 200)

    # Should have three entities, one matched, all functions and all with the name "Hello".
    overloaded = list(get_overloaded_functions(db))
    assert [func.sequence for func in overloaded] == [1, 2, 3]
    assert [func.orig_addr for func in overloaded] == [100, 200, None]
    assert [func.recomp_addr for func in overloaded] == [None, 200, 300]
