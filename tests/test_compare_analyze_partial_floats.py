import pytest
from reccmp.isledecomp.compare.analyze import (
    complete_partial_floats,
)
from reccmp.isledecomp.types import EntityType, ImageId
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.formats import PEImage


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


@pytest.mark.parametrize("image_id", ImageId)
def test_complete_partial_floats(db: EntityDb, binfile: PEImage, image_id: ImageId):
    floats = (
        (0x100D5740, 4, "0.0"),
        (0x100D5748, 8, "0.0"),
        (0x100D5750, 4, "10000.0"),
        (0x100D5858, 4, "5000.0"),
    )

    with db.batch() as batch:
        for addr, size, _ in floats:
            batch.set(image_id, addr, type=EntityType.FLOAT, size=size)

    complete_partial_floats(db, image_id, binfile)

    for addr, _, value in floats:
        e = db.get(image_id, addr)
        assert e is not None
        assert e.get("name") == value


@pytest.mark.parametrize("image_id", ImageId)
def test_complete_partial_floats_do_not_overwrite(
    db: EntityDb, binfile: PEImage, image_id: ImageId
):
    """If a float entity already has a name (for whatever reason) then leave it alone."""
    with db.batch() as batch:
        batch.set(image_id, 0x100D5740, type=EntityType.FLOAT, size=4, name="MyFloat")

    complete_partial_floats(db, image_id, binfile)

    entity = db.get(image_id, 0x100D5740)
    assert entity is not None
    assert entity.get("name") == "MyFloat"


@pytest.mark.parametrize("image_id", ImageId)
def test_complete_partial_floats_invalid_addr(
    db: EntityDb, binfile: PEImage, image_id: ImageId
):
    """Should catch any exceptions raised by reading an invalid address."""
    with db.batch() as batch:
        # Address outside image range
        batch.set(image_id, 0x110D5740, type=EntityType.FLOAT, size=4)
        # Cannot read 8 bytes from here
        batch.set(image_id, 0x100EF5FE, type=EntityType.FLOAT, size=8)

    complete_partial_floats(db, image_id, binfile)


@pytest.mark.parametrize("image_id", ImageId)
def test_complete_partial_floats_invalid_size(
    db: EntityDb, binfile: PEImage, image_id: ImageId
):
    """Should ignore float entities with size that is not 4 or 8 bytes."""
    with db.batch() as batch:
        batch.set(image_id, 0x100D5740, type=EntityType.FLOAT, size=3)
        batch.set(image_id, 0x100D5748, type=EntityType.FLOAT)

    complete_partial_floats(db, image_id, binfile)

    for addr in (0x100D5740, 0x100D5748):
        entity = db.get(image_id, addr)
        assert entity is not None
        # Should not set a name. We did not try to read the data.
        assert entity.get("name") is None


@pytest.mark.parametrize("image_id", ImageId)
def test_complete_partial_floats_matched(
    db: EntityDb, binfile: PEImage, image_id: ImageId
):
    """Will update matched entities by reading from whichever binary is provided."""
    with db.batch() as batch:
        batch.set_recomp(0x100D5748, type=EntityType.FLOAT, size=8)
        batch.match(0x100D5748, 0x100D5748)

    # Parametrized so we will use both address spaces as the key.
    complete_partial_floats(db, image_id, binfile)

    entity = db.get(image_id, 0x100D5748)
    assert entity is not None
    assert entity.get("name") == "0.0"


def test_complete_partial_floats_invalid_id(db: EntityDb, binfile: PEImage):
    with pytest.raises(AssertionError):
        complete_partial_floats(db, 2, binfile)  # type: ignore
