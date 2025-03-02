import pytest
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.compare.asm.replacement import (
    create_name_lookup,
    NameReplacementProtocol,
)


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


def create_lookup(
    db, addrs: dict[int, int] | None = None, is_orig: bool = True
) -> NameReplacementProtocol:
    if addrs is None:
        addrs = {}

    def bin_lookup(addr: int) -> int | None:
        return addrs.get(addr)

    if is_orig:
        return create_name_lookup(db.get_by_orig, bin_lookup, "orig_addr")

    return create_name_lookup(db.get_by_recomp, bin_lookup, "recomp_addr")


####


def test_name_replacement(db):
    """Should return a name for an entity that has one.
    Return None if there are no name attributes set or the entity does not exist."""
    with db.batch() as batch:
        batch.set_orig(100, name="Test")
        batch.set_orig(200, computed_name="Hello")
        batch.set_orig(300)  # No name

    lookup = create_lookup(db)

    # Using "in" here because the returned string may contain other information.
    # e.g. the entity type
    assert "Test" in lookup(100)
    assert "Hello" in lookup(200)
    assert lookup(300) is None


def test_name_hierarchy(db):
    """Use the "best" entity name. Currently there are only two.
    'computed_name' is preferred over just 'name'."""
    with db.batch() as batch:
        batch.set_orig(100, name="Test", computed_name="Hello")

    lookup = create_lookup(db)

    # Should prefer 'computed_name' over 'name'
    assert "Hello" in lookup(100)
    assert "Test" not in lookup(100)


def test_string_escape_newlines(db):
    """Make sure newlines are removed from the string.
    This overlap with tests on the ReccmpEntity name functions, but it is more vital
    to ensure there are no newlines at this stage because they will disrupt the asm diff.
    """
    with db.batch() as batch:
        batch.set_orig(100, name="Test\nTest", type=EntityType.STRING)

    lookup = create_lookup(db)

    assert "\n" not in lookup(100)


def test_offset_name(db):
    """For some entities (i.e. variables) we will return a name if the search address
    is inside the address range of the entity. This is determined by the size attribute.
    """
    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.DATA, size=10)

    lookup = create_lookup(db)

    assert lookup(100) is not None
    assert lookup(101) is not None

    # Outside the range = no name
    assert lookup(110) is None


def test_offset_name_non_variables(db):
    """Do not return an offset name for non-variable entities. (e.g. functions)."""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION, size=10)
        batch.set_orig(200, name="Hello", size=10)  # No type

    lookup = create_lookup(db)

    assert lookup(100) is not None
    assert lookup(101) is None

    assert lookup(200) is not None
    assert lookup(201) is None


def test_offset_name_no_size(db):
    """An enity with no size attribute is considered to have size=0.
    Meaning: match only against the address value."""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.DATA)

    lookup = create_lookup(db)

    assert lookup(100) is not None
    assert lookup(101) is None


def test_exact_restriction(db):
    """If exact=True, return a name only if the entity's address matches the search address.
    Otherwise we might return a name if the entity contains the search address."""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.DATA, size=10)

    lookup = create_lookup(db)

    assert lookup(100, exact=True) is not None
    assert lookup(101, exact=True) is None

    # Proof that the exact parameter controls whether we get a name.
    assert lookup(101, exact=False) is not None


def test_indirect_function(db):
    """An instruction like `call dword ptr [0x1234]` means that we call the function
    whose address is at address 0x1234. This is an indirect lookup."""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)

    # Mock lookup so we will read 100 from address 200.
    lookup = create_lookup(db, {200: 100})

    # No entity at 200
    assert lookup(200) is None
    assert lookup(200, indirect=True) is not None

    # Imitating ghidra asm display. Not every indirect lookup gets the arrow.
    assert "->" in lookup(200, indirect=True)


def test_indirect_function_variable(db):
    """If the indirect call instruction has the address of a variable in our database,
    prefer the variable name rather than reading the pointer."""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello", type=EntityType.FUNCTION)
        batch.set_orig(200, name="Test", type=EntityType.DATA)

    # Mock lookup so we will read 100 from address 200.
    lookup = create_lookup(db, {200: 100})

    name = lookup(200, indirect=True)
    assert name is not None
    assert "Hello" not in name
    assert "Test" in name
    assert "->" not in name


def test_indirect_import(db):
    """If we are indirectly calling an imported funtion, we should see the import_name
    attribute used in the result. This will probably contain the DLL and function name.
    """
    with db.batch() as batch:
        batch.set_orig(100, import_name="Hello", name="Test", type=EntityType.IMPORT)

    # No mock needed here because we will not need to read any data.
    lookup = create_lookup(db)

    # Should use import name with arrow to suggest indirect call.
    name = lookup(100, indirect=True)
    assert name is not None
    assert "Hello" in name
    assert "->" in name

    # Show the entity name instead. (e.g. __imp__ symbol)
    name = lookup(100, indirect=False)
    assert name is not None
    assert "Test" in name
    assert "->" not in name


def test_indirect_import_missing_data(db):
    """Edge cases for indirect lookup on an IMPORT entity.."""
    with db.batch() as batch:
        batch.set_orig(100, name="Test", type=EntityType.IMPORT)

    lookup = create_lookup(db)

    # No import name. Use the regular entity name instead (i.e. match indirect=False lookup)
    name = lookup(100, indirect=True)
    assert name is not None
    assert "Test" in name
    assert "->" not in name


def test_indirect_failed_lookup(db):
    """In the general case (i.e. we do not use the base entity to get the name)
    if there is no entity at the pointer location, return None."""
    with db.batch() as batch:
        batch.set_orig(200, name="Hello", type=EntityType.FUNCTION)

    # Mock lookup so we will read 100 from address 200.
    lookup = create_lookup(db, {200: 100})

    # There is an entity at 200 but we can't use it to generate a name.
    # There is no entity at 100 (indirect location)
    assert lookup(200, indirect=False) is not None
    assert lookup(200, indirect=True) is None
