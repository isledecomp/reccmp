import pytest
from reccmp.isledecomp.compare.mutate import (
    name_thunks,
)
from reccmp.isledecomp.types import EntityType, ImageId
from reccmp.isledecomp.compare.db import EntityDb


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


# n.b. In these tests, parametrize iterates over the ImageId enum to get: (ImageId.ORIG, ImageId.RECOMP)


@pytest.mark.parametrize("image_id", ImageId)
def test_name_thunks(db: EntityDb, image_id: ImageId):
    """Should provide a name for the thunk entity if the link back to the function is valid."""
    with db.batch() as batch:
        batch.set(image_id, 100, type=EntityType.FUNCTION, name="Hello")
        batch.set(image_id, 200, type=EntityType.THUNK)
        batch.set_ref(image_id, 200, ref=100)

    name_thunks(db)

    e = db.get(image_id, 200)
    assert e is not None
    name = e.get("name")
    assert name is not None
    assert "Hello" in name


@pytest.mark.parametrize("image_id", ImageId)
def test_name_thunks_vtordisp(db: EntityDb, image_id: ImageId):
    """The name_thunks function also applies the vtordisp suffix if displacement is non-zero."""
    with db.batch() as batch:
        batch.set(image_id, 100, type=EntityType.FUNCTION, name="Hello")
        batch.set(image_id, 200, type=EntityType.VTORDISP)
        batch.set_ref(image_id, 200, ref=100, displacement=(-4, 0))

    name_thunks(db)

    e = db.get(image_id, 200)
    assert e is not None
    name = e.get("name")
    assert name is not None
    assert "Hello" in name
    # Allowing for future format changes.
    assert "vtordisp" in name
    assert "-4, 0" in name


@pytest.mark.parametrize("image_id", ImageId)
def test_name_thunks_chained(db: EntityDb, image_id: ImageId):
    """Should name each thunk in a chain of child entities."""
    with db.batch() as batch:
        batch.set(image_id, 100, type=EntityType.FUNCTION, name="Hello")
        batch.set(image_id, 200, type=EntityType.THUNK)
        batch.set(image_id, 300, type=EntityType.THUNK)
        batch.set_ref(image_id, 200, ref=100)
        batch.set_ref(image_id, 300, ref=200)

    name_thunks(db)

    for addr in (200, 300):
        e = db.get(image_id, addr)
        assert e is not None
        name = e.get("name")
        assert name is not None
        assert "Hello" in name


@pytest.mark.parametrize("image_id", ImageId)
def test_name_thunks_ignore_child_no_type(db: EntityDb, image_id: ImageId):
    """The referencing entity has no type. Should not rename."""
    with db.batch() as batch:
        batch.set(image_id, 100, type=EntityType.FUNCTION, name="Hello")
        batch.set(image_id, 200)
        batch.set_ref(image_id, 200, ref=100)

    name_thunks(db)

    e = db.get(image_id, 200)
    assert e is not None
    assert e.get("name") is None


@pytest.mark.parametrize("image_id", ImageId)
def test_name_thunks_ignore_child_not_thunk(db: EntityDb, image_id: ImageId):
    """The referencing entity is not a thunk. Should not rename."""
    with db.batch() as batch:
        batch.set(image_id, 100, type=EntityType.FUNCTION, name="Hello")
        batch.set(image_id, 200, type=EntityType.FUNCTION)
        batch.set_ref(image_id, 200, ref=100)

    name_thunks(db)

    e = db.get(image_id, 200)
    assert e is not None
    assert e.get("name") is None


@pytest.mark.parametrize("image_id", ImageId)
def test_name_thunks_unique_name(db: EntityDb, image_id: ImageId):
    """Use the unique name (computed_name) for the thunk if it exists."""
    # Establish a function and thunk.
    with db.batch() as batch:
        batch.set(
            image_id, 100, type=EntityType.FUNCTION, name="Hello", computed_name="Test"
        )
        batch.set(image_id, 200, type=EntityType.THUNK)
        batch.set_ref(image_id, 200, ref=100)

    name_thunks(db)

    e = db.get(image_id, 200)
    assert e is not None
    name = e.get("name")
    assert name is not None
    assert "Hello" not in name
    assert "Test" in name


@pytest.mark.parametrize("image_id", ImageId)
def test_name_thunks_ref_not_function(db: EntityDb, image_id: ImageId):
    """Should not set a name if the entity referenced by the thunk is not a function."""
    with db.batch() as batch:
        batch.set(image_id, 100, name="Hello")
        batch.set(image_id, 200, type=EntityType.THUNK)
        batch.set_ref(image_id, 200, ref=100)

    name_thunks(db)

    e = db.get(image_id, 200)
    assert e is not None
    assert e.get("name") is None


@pytest.mark.parametrize("image_id", ImageId)
def test_name_thunks_ref_does_not_exist(db: EntityDb, image_id: ImageId):
    """Should not set a name if the entity referenced by the thunk does not exist."""
    with db.batch() as batch:
        batch.set(image_id, 200, ref=100)

    name_thunks(db)

    e = db.get(image_id, 200)
    assert e is not None
    assert e.get("name") is None


def test_name_thunks_ref_crossed(db: EntityDb):
    """Should not set a name for a thunk if ref_orig and ref_recomp point to different entities."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.FUNCTION, name="Hello")
        batch.set(ImageId.ORIG, 200, ref=100)
        batch.set(ImageId.RECOMP, 100, type=EntityType.FUNCTION, name="World")
        batch.set(ImageId.RECOMP, 200, ref=100)
        # Match the thunks but not the referenced functions.
        batch.match(200, 200)

    name_thunks(db)

    e = db.get(ImageId.ORIG, 200)
    assert e is not None
    assert e.get("name") is None

    e = db.get(ImageId.RECOMP, 200)
    assert e is not None
    assert e.get("name") is None
