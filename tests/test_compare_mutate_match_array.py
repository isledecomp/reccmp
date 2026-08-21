"""Tests for offset name substitution that imitate the behavior of the removed `match_array_elements` function."""

from functools import partial
import pytest
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb
from reccmp.cvdump.types import CvdumpTypesParser, FieldListItem, CVInfoTypeEnum
from reccmp.cvdump.cvinfo import CvdumpTypeKey as TK

# pylint:disable=protected-access
# TODO: Remove after we no longer access `types_db._keys` directly. See #485.


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


@pytest.fixture(name="types_db")
def fixture_types() -> CvdumpTypesParser:
    return CvdumpTypesParser()


def name_for_address(
    db: EntityDb, types_db: CvdumpTypesParser, image_id: ImageId, addr: int
) -> str:
    """It would be better to test the real code path instead. GH #461"""
    entity = db.get(image_id, addr, exact=False)
    assert entity is not None
    base_addr = entity.addr(image_id)
    assert isinstance(base_addr, int)
    offset = addr - base_addr

    suffix = ""
    type_key = entity.get("data_type")
    if isinstance(type_key, int):
        suffix = types_db.get_name_for_offset(TK(type_key), offset)

    name = entity.name
    if name:
        return name + suffix

    return ""


def test_match_array(db: EntityDb, types_db: CvdumpTypesParser):
    """Should rename the entity for the array and create a new entity for the second member."""
    types_db._keys[TK(0x1000)] = {
        "type": "LF_ARRAY",
        "array_type": CVInfoTypeEnum.T_REAL32,
        "size": 8,
    }

    with db.batch() as batch:
        # NOTE: It does not work if entity size is not set.
        # We should be able to set it because how else would we have the type key?
        batch.set(
            ImageId.RECOMP,
            100,
            name="test",
            type=EntityType.DATA,
            data_type=0x1000,
            size=8,
        )
        batch.match(100, 100)

    get_name = partial(name_for_address, db, types_db)

    assert get_name(ImageId.ORIG, 100) == "test[0]"
    assert get_name(ImageId.ORIG, 104) == "test[1]"
    assert get_name(ImageId.RECOMP, 100) == "test[0]"
    assert get_name(ImageId.RECOMP, 104) == "test[1]"


def test_match_array_key_unset(db: EntityDb):
    """Should have no effect if the data_type key is not in the types database."""
    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            100,
            name="test",
            type=EntityType.DATA,
            data_type=0x1000,
            size=8,
        )
        batch.match(100, 100)

    # Empty types db so the key lookup will fail
    get_name = partial(name_for_address, db, CvdumpTypesParser())

    assert get_name(ImageId.ORIG, 100) == "test"
    assert get_name(ImageId.ORIG, 104) == "test+4"
    assert get_name(ImageId.RECOMP, 100) == "test"
    assert get_name(ImageId.RECOMP, 104) == "test+4"


def test_match_array_type_is_scalar(db: EntityDb):
    """Should have no effect if the data_type key is a scalar.
    TODO: The expectation will change slightly when the type database does. #211"""
    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            100,
            name="test",
            type=EntityType.DATA,
            data_type=CVInfoTypeEnum.T_REAL32,
            size=8,
        )
        batch.match(100, 100)

    # Scalars are not currently part of the type database dict, so use an empty one.
    get_name = partial(name_for_address, db, CvdumpTypesParser())

    assert get_name(ImageId.ORIG, 100) == "test"
    assert get_name(ImageId.ORIG, 104) == "test+4"
    assert get_name(ImageId.RECOMP, 100) == "test"
    assert get_name(ImageId.RECOMP, 104) == "test+4"


def test_match_array_type_is_struct(db: EntityDb, types_db: CvdumpTypesParser):
    """Should have no effect if the data_type key is not an array.
    We do not currently populate entities for struct members."""
    types_db._keys[TK(0x1000)] = {
        "type": "LF_STRUCTURE",
        "field_list_type": TK(0x1001),
        "size": 8,
    }
    types_db._keys[TK(0x1001)] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="hello", type=CVInfoTypeEnum.T_REAL32),
            FieldListItem(offset=4, name="world", type=CVInfoTypeEnum.T_REAL32),
        ],
    }

    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            100,
            name="test",
            type=EntityType.DATA,
            data_type=0x1000,
            size=8,
        )
        batch.match(100, 100)

    # Empty types db so the key lookup will fail
    get_name = partial(name_for_address, db, CvdumpTypesParser())

    assert get_name(ImageId.ORIG, 100) == "test"
    assert get_name(ImageId.ORIG, 104) == "test+4"
    assert get_name(ImageId.RECOMP, 100) == "test"
    assert get_name(ImageId.RECOMP, 104) == "test+4"


def test_match_array_type_orig_smaller(db: EntityDb, types_db: CvdumpTypesParser):
    """Should not create entities on the orig side if the array is known to be smaller.
    (i.e. if another DATA entity is in the way.)"""
    types_db._keys[TK(0x1000)] = {
        "type": "LF_ARRAY",
        "array_type": CVInfoTypeEnum.T_REAL32,
        "size": 8,
    }

    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            100,
            name="test",
            type=EntityType.DATA,
            data_type=0x1000,
            size=8,
        )
        # Set the max size (i.e. distance to "blocker" entity) manually.
        # It was previously calculated inside match_array_elements.
        batch.set(ImageId.ORIG, 100, max_size=4)
        batch.set(ImageId.ORIG, 104, name="blocker", type=EntityType.DATA)
        batch.match(100, 100)

    get_name = partial(name_for_address, db, types_db)

    assert get_name(ImageId.ORIG, 100) == "test[0]"
    assert get_name(ImageId.ORIG, 104) == "blocker"
    assert get_name(ImageId.RECOMP, 100) == "test[0]"
    assert get_name(ImageId.RECOMP, 104) == "test[1]"


def test_match_array_array_of_structs(db: EntityDb, types_db: CvdumpTypesParser):
    """If the type is an array of structs, create entities for one level of struct members."""
    types_db._keys[TK(0x1000)] = {
        "type": "LF_ARRAY",
        "array_type": TK(0x1001),
        "size": 16,
    }
    types_db._keys[TK(0x1001)] = {
        "type": "LF_STRUCTURE",
        "field_list_type": TK(0x1002),
        "size": 8,
    }
    types_db._keys[TK(0x1002)] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="hello", type=CVInfoTypeEnum.T_REAL32),
            FieldListItem(offset=4, name="world", type=CVInfoTypeEnum.T_REAL32),
        ],
    }

    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            100,
            name="test",
            type=EntityType.DATA,
            data_type=0x1000,
            size=16,
        )
        batch.match(100, 100)

    get_name = partial(name_for_address, db, types_db)

    assert get_name(ImageId.ORIG, 100) == "test[0].hello"
    assert get_name(ImageId.ORIG, 104) == "test[0].world"
    assert get_name(ImageId.ORIG, 108) == "test[1].hello"
    assert get_name(ImageId.ORIG, 112) == "test[1].world"
    assert get_name(ImageId.RECOMP, 100) == "test[0].hello"
    assert get_name(ImageId.RECOMP, 104) == "test[0].world"
    assert get_name(ImageId.RECOMP, 108) == "test[1].hello"
    assert get_name(ImageId.RECOMP, 112) == "test[1].world"


def test_match_array_array_of_arrays(db: EntityDb, types_db: CvdumpTypesParser):
    """For a multi-dimensional array, create entities for one level."""
    types_db._keys[TK(0x1000)] = {
        "type": "LF_ARRAY",
        "array_type": TK(0x1001),
        "size": 16,
    }
    types_db._keys[TK(0x1001)] = {
        "type": "LF_ARRAY",
        "array_type": CVInfoTypeEnum.T_REAL32,
        "size": 8,
    }

    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            100,
            name="test",
            type=EntityType.DATA,
            data_type=0x1000,
            size=16,
        )
        batch.match(100, 100)

    get_name = partial(name_for_address, db, types_db)

    assert get_name(ImageId.ORIG, 100) == "test[0][0]"
    assert get_name(ImageId.ORIG, 104) == "test[0][1]"
    assert get_name(ImageId.ORIG, 108) == "test[1][0]"
    assert get_name(ImageId.ORIG, 112) == "test[1][1]"
    assert get_name(ImageId.RECOMP, 100) == "test[0][0]"
    assert get_name(ImageId.RECOMP, 104) == "test[0][1]"
    assert get_name(ImageId.RECOMP, 108) == "test[1][0]"
    assert get_name(ImageId.RECOMP, 112) == "test[1][1]"


def test_match_array_array_of_structs_limit(db: EntityDb, types_db: CvdumpTypesParser):
    """Does not create entities for offsets more than one level beyond the main entity."""
    types_db._keys[TK(0x1000)] = {
        "type": "LF_ARRAY",
        "array_type": TK(0x1001),
        "size": 16,
    }
    types_db._keys[TK(0x1001)] = {
        "type": "LF_STRUCTURE",
        "field_list_type": TK(0x1002),
        "size": 8,
    }
    types_db._keys[TK(0x1002)] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="hello", type=TK(0x1003)),
            FieldListItem(offset=4, name="world", type=TK(0x1003)),
        ],
    }
    types_db._keys[TK(0x1003)] = {
        "type": "LF_STRUCTURE",
        "field_list_type": TK(0x1004),
        "size": 4,
    }
    types_db._keys[TK(0x1004)] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="x", type=CVInfoTypeEnum.T_SHORT),
            FieldListItem(offset=2, name="y", type=CVInfoTypeEnum.T_SHORT),
        ],
    }

    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            100,
            name="test",
            type=EntityType.DATA,
            data_type=0x1000,
            size=16,
        )
        batch.match(100, 100)

    get_name = partial(name_for_address, db, types_db)

    assert get_name(ImageId.ORIG, 100) == "test[0].hello"
    assert get_name(ImageId.ORIG, 104) == "test[0].world"
    assert get_name(ImageId.ORIG, 108) == "test[1].hello"
    assert get_name(ImageId.ORIG, 112) == "test[1].world"
    assert get_name(ImageId.RECOMP, 100) == "test[0].hello"
    assert get_name(ImageId.RECOMP, 104) == "test[0].world"
    assert get_name(ImageId.RECOMP, 108) == "test[1].hello"
    assert get_name(ImageId.RECOMP, 112) == "test[1].world"


def test_match_array_array_of_union_structs(db: EntityDb, types_db: CvdumpTypesParser):
    """GH issue #289. Demonstrating the following behavior:
    - We use the name from the first option in the union
    - We create offset entities for unions, as with a struct or multidimensional array
    - We will not create entities deeper than the second level (in this case, array -> union)
    """
    types_db._keys[TK(0x1000)] = {
        "type": "LF_ARRAY",
        "array_type": TK(0x1001),
        "size": 8,
    }
    types_db._keys[TK(0x1001)] = {
        "type": "LF_UNION",
        "field_list_type": TK(0x1002),
        "size": 4,
    }
    types_db._keys[TK(0x1002)] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="hello", type=TK(0x1003)),
            FieldListItem(offset=0, name="world", type=TK(0x1003)),
        ],
    }
    # These values will not be accessed because we do not completely flatten the structure.
    # But they are here to provide a complete example of type data.
    types_db._keys[TK(0x1003)] = {
        "type": "LF_STRUCTURE",
        "field_list_type": TK(0x1004),
        "size": 4,
    }
    types_db._keys[TK(0x1004)] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="a", type=CVInfoTypeEnum.T_CHAR),
            FieldListItem(offset=1, name="b", type=CVInfoTypeEnum.T_CHAR),
            FieldListItem(offset=2, name="c", type=CVInfoTypeEnum.T_CHAR),
            FieldListItem(offset=3, name="d", type=CVInfoTypeEnum.T_CHAR),
        ],
    }

    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            100,
            name="test",
            type=EntityType.DATA,
            data_type=0x1000,
            size=8,
        )
        batch.match(100, 100)

    get_name = partial(name_for_address, db, types_db)

    assert get_name(ImageId.ORIG, 100) == "test[0].hello"
    assert get_name(ImageId.ORIG, 104) == "test[1].hello"
    assert get_name(ImageId.RECOMP, 100) == "test[0].hello"
    assert get_name(ImageId.RECOMP, 104) == "test[1].hello"


def test_match_array_of_struct_bitfield(db: EntityDb, types_db: CvdumpTypesParser):
    """Verify comparing an array of struct bitfields uses the underlying type of the bitfield"""
    types_db._keys[TK(0x1000)] = {
        "type": "LF_ARRAY",
        "array_type": TK(0x1001),
        "size": 4 * 8,
    }
    types_db._keys[TK(0x1001)] = {
        "type": "LF_STRUCTURE",
        "field_list_type": TK(0x1002),
        "size": 8,
    }
    types_db._keys[TK(0x1002)] = {
        "type": "LF_FIELDLIST",
        "members": [
            FieldListItem(offset=0, name="v0", type=CVInfoTypeEnum.T_UINT4),
            FieldListItem(offset=4, name="bit0", type=TK(0x1003)),
            FieldListItem(offset=4, name="bit1", type=TK(0x1004)),
        ],
    }
    types_db._keys[TK(0x1003)] = {
        "type": "LF_BITFIELD",
        "bit_start": 0,
        "bit_count": 1,
        "bit_type": CVInfoTypeEnum.T_UCHAR,
    }
    types_db._keys[TK(0x1004)] = {
        "type": "LF_BITFIELD",
        "bit_start": 1,
        "bit_count": 1,
        "bit_type": CVInfoTypeEnum.T_UCHAR,
    }

    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            0x100,
            name="test",
            type=EntityType.DATA,
            data_type=0x1000,
            size=32,
        )
        batch.match(0x100, 0x100)

    get_name = partial(name_for_address, db, types_db)

    assert get_name(ImageId.ORIG, 0x100) == "test[0].v0"
    assert get_name(ImageId.RECOMP, 0x118) == "test[3].v0"
    assert get_name(ImageId.RECOMP, 0x11C) == "test[3].bit0"
