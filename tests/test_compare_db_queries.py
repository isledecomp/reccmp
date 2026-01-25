"""Testing results of complex queries on the entity database"""

import pytest
from reccmp.compare.db import EntityDb
from reccmp.compare.queries import (
    get_overloaded_functions,
    get_referencing_entity_matches,
    get_floats_without_data,
    get_strings_without_data,
)
from reccmp.types import EntityType, ImageId


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


def test_get_referencing_entity_matches(db: EntityDb):
    """Demo of the behavior for the test_get_referencing_entity_matches query.
    It should returns only new matches for child entities."""

    # Set up matched parent entity.
    with db.batch() as batch:
        batch.set_orig(100)
        batch.set_recomp(100)
        batch.match(100, 100)

    # There are no referencing entities.
    assert not list(get_referencing_entity_matches(db))

    # Set up child entities with reference link.
    with db.batch() as batch:
        batch.set_orig(200)
        batch.set_recomp(300)

        batch.set_ref(ImageId.ORIG, 200, ref=100)
        batch.set_ref(ImageId.RECOMP, 300, ref=100)

    # Can match these child entities that point to the same matched parent.
    assert list(get_referencing_entity_matches(db)) == [(200, 300)]

    # Create the match as directed by the query.
    with db.batch() as batch:
        batch.match(200, 300)

    # All child entities have already been matched.
    assert not list(get_referencing_entity_matches(db))


@pytest.mark.xfail(reason="Will match child entities of different types.")
def test_get_referencing_entity_matches_check_entity_type(db: EntityDb):
    """Possible future behavior of the query: require types of child entities
    to match along with checking reference and displacement values."""
    with db.batch() as batch:
        batch.set_orig(100)
        batch.set_recomp(100)
        batch.match(100, 100)

        batch.set_orig(200, type=EntityType.THUNK)
        batch.set_recomp(300, type=EntityType.FUNCTION)

        batch.set_ref(ImageId.ORIG, 200, ref=100)
        batch.set_ref(ImageId.RECOMP, 300, ref=100)

    # Should not return any matches: child entities have different type.
    assert not list(get_referencing_entity_matches(db))


@pytest.mark.parametrize("image_id", ImageId)
def test_get_floats_without_data(db: EntityDb, image_id: ImageId):
    assert not list(get_floats_without_data(db, image_id))

    with db.batch() as batch:
        # No size.
        batch.set(image_id, 100, type=EntityType.FLOAT)
        # Already has data.
        batch.set(image_id, 200, type=EntityType.FLOAT, size=4, name="0.5")
        # Invalid size.
        batch.set(image_id, 300, type=EntityType.FLOAT, size=10)

    assert not list(get_floats_without_data(db, image_id))

    with db.batch() as batch:
        # Single and double-precision floats without data.
        batch.set(image_id, 400, type=EntityType.FLOAT, size=4)
        batch.set(image_id, 500, type=EntityType.FLOAT, size=8)

    assert list(get_floats_without_data(db, image_id)) == [(400, False), (500, True)]


@pytest.mark.parametrize("image_id", ImageId)
def test_get_strings_without_data(db: EntityDb, image_id: ImageId):
    assert not list(get_strings_without_data(db, image_id))

    with db.batch() as batch:
        # String entities with data already set.
        batch.set(image_id, 100, type=EntityType.STRING, name='"Test"')
        batch.set(image_id, 200, type=EntityType.WIDECHAR, name='L"Test"')

    assert not list(get_strings_without_data(db, image_id))

    with db.batch() as batch:
        # Strings without a known size.
        batch.set(image_id, 300, type=EntityType.STRING)
        batch.set(image_id, 400, type=EntityType.WIDECHAR)

    assert list(get_strings_without_data(db, image_id)) == [
        (300, None, False),
        (400, None, True),
    ]

    with db.batch() as batch:
        # Set a size for the strings.
        batch.set(image_id, 300, size=5)
        batch.set(image_id, 400, size=10)

    assert list(get_strings_without_data(db, image_id)) == [
        (300, 5, False),
        (400, 10, True),
    ]
