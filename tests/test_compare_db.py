"""Testing compare database behavior, particularly matching"""

import sqlite3
from unittest.mock import patch
import pytest
from reccmp.isledecomp.compare.db import EntityDb


@pytest.fixture(name="db")
def fixture_db():
    return EntityDb()


def test_ignore_recomp_collision(db):
    """Duplicate recomp addresses are ignored"""
    db.set_recomp_symbol(0x1234, name="hello", size=100)
    db.set_recomp_symbol(0x1234, name="alias_for_hello", size=100)
    syms = [*db.get_all()]
    assert len(syms) == 1


def test_orig_collision(db):
    """Don't match if the original address is not unique"""
    db.set_recomp_symbol(0x1234, name="hello", size=100)
    assert db.match_function(0x5555, "hello") is True

    # Second run on same address fails
    assert db.match_function(0x5555, "hello") is False

    # Call set_pair directly without wrapper
    assert db.set_pair(0x5555, 0x1234) is False


def test_name_match(db):
    db.set_recomp_symbol(0x1234, name="hello", size=100)
    assert db.match_function(0x5555, "hello") is True

    match = db.get_by_orig(0x5555)
    assert match.name == "hello"
    assert match.recomp_addr == 0x1234


def test_match_decorated(db):
    """Should match using decorated name even though regular name is null"""
    db.set_recomp_symbol(0x1234, symbol="?_hello", size=100)
    assert db.match_function(0x5555, "?_hello") is True
    match = db.get_by_orig(0x5555)
    assert match is not None


def test_duplicate_name(db):
    """If recomp name is not unique, match only one row"""
    db.set_recomp_symbol(0x100, name="_Construct", size=100)
    db.set_recomp_symbol(0x200, name="_Construct", size=100)
    db.set_recomp_symbol(0x300, name="_Construct", size=100)
    db.match_function(0x5555, "_Construct")
    matches = [*db.get_matches()]
    # We aren't testing _which_ one would be matched, just that only one _was_ matched
    assert len(matches) == 1


def test_static_variable_match(db):
    """Set up a situation where we can match a static function variable, then match it."""

    # We need a matched function to start with.
    db.set_recomp_symbol(
        0x1234, name="Isle::Tick", symbol="?Tick@IsleApp@@QAEXH@Z", size=100
    )
    db.match_function(0x5555, "Isle::Tick")

    # Decorated variable name from PDB.
    db.set_recomp_symbol(
        0x2000, symbol="?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA", size=4
    )

    # Provide variable name and orig function address from decomp markers
    assert db.match_static_variable(0xBEEF, "g_startupDelay", 0x5555) is True


def test_dynamic_metadata(db):
    """Using the API we have now"""
    db.set_recomp_symbol(1234, hello="abcdef", option=True)
    obj = db.get_by_recomp(1234)
    assert obj.get("hello") == "abcdef"

    # Should preserve boolean type
    assert isinstance(obj.get("option"), bool)
    assert obj.get("option") is True


def test_db_count(db):
    """Wrapper around SELECT COUNT"""
    assert db.count() == 0

    with db.batch() as batch:
        batch.set_orig(100)
        batch.set_recomp(100)

    assert db.count() == 2

    with db.batch() as batch:
        batch.match(100, 100)

    assert db.count() == 1


#### Testing new batch API ####


def test_batch(db):
    """Demonstrate batch with context manager"""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello")
        batch.set_recomp(200, name="Test")

    assert db.get_by_orig(100).name == "Hello"
    assert db.get_by_recomp(200).name == "Test"


def test_batch_replace(db):
    """Calling the set or insert methods again on the same address and data will replace the pending value."""
    with db.batch() as batch:
        batch.set_orig(100, name="")
        batch.insert_orig(200, name="")
        batch.set_recomp(100, name="")
        batch.insert_recomp(200, name="")

        batch.set_orig(100, name="Orig100")
        batch.insert_orig(200, name="Orig200")
        batch.set_recomp(100, name="Recomp100")
        batch.insert_recomp(200, name="Recomp200")

    assert db.get_by_orig(100).name == "Orig100"
    assert db.get_by_orig(200).name == "Orig200"
    assert db.get_by_recomp(100).name == "Recomp100"
    assert db.get_by_recomp(200).name == "Recomp200"


def test_batch_insert_overwrite(db):
    """Inserts and sets on the same address in the same batch will result in the
    'insert' values being replaced."""
    with db.batch() as batch:
        batch.insert_orig(100, name="Test")
        batch.set_orig(100, name="Hello", test=123)
        batch.insert_recomp(100, name="Test")
        batch.set_recomp(100, name="Hello", test=123)

    assert db.get_by_orig(100).name == "Hello"
    assert db.get_by_orig(100).get("test") == 123

    assert db.get_by_recomp(100).name == "Hello"
    assert db.get_by_recomp(100).get("test") == 123


def test_batch_insert(db):
    """The 'insert' methods will abort if any data exists for the address"""
    db.set_orig_symbol(100, name="Hello")
    db.set_recomp_symbol(200, name="Test")

    with db.batch() as batch:
        batch.insert_orig(100, name="abc")
        batch.insert_recomp(200, name="xyz")

    assert db.get_by_orig(100).name != "abc"
    assert db.get_by_recomp(200).name != "xyz"


def test_batch_upsert(db):
    """The 'set' methods overwrite existing values"""
    db.set_orig_symbol(100, name="Hello")
    db.set_recomp_symbol(200, name="Test")

    with db.batch() as batch:
        batch.set_orig(100, name="abc")
        batch.set_recomp(200, name="xyz")

    assert db.get_by_orig(100).name == "abc"
    assert db.get_by_recomp(200).name == "xyz"


def test_batch_match_attach(db):
    """Match example with new orig addr.
    There is no existing entity with the orig addr being matched."""
    with db.batch() as batch:
        batch.set_recomp(200, name="Hello")
        batch.match(100, 200)

    # Confirm match
    assert db.get_by_orig(100).name == "Hello"


def test_batch_match_combine(db):
    """Match example with existing orig addr."""
    with db.batch() as batch:
        batch.set_orig(100, name="Test")
        batch.set_recomp(200, name="Hello")

    # Two entities
    assert len([*db.get_all()]) == 2

    # Use separate batches to demonstrate
    with db.batch() as batch:
        batch.match(100, 200)

    # Should combine
    assert len([*db.get_all()]) == 1

    # Confirm match. Both entities have the "name" attribute. Should use recomp value.
    assert db.get_by_orig(100).recomp_addr == 200
    assert db.get_by_orig(100).name == "Hello"


def test_batch_match_combine_except_null(db):
    """We prefer recomp attributes when combining two entities.
    The exception is when the recomp entity has a NULL. We should use the orig attribute in this case.
    """
    with db.batch() as batch:
        batch.set_orig(100, name="Test", test=123)
        batch.set_recomp(200, name="Hello", test=None)
        batch.match(100, 200)

    assert db.get_by_recomp(200).get("test") == 123


def test_batch_match_combine_replace_null(db):
    """Confirm that we will replace a NULL on the orig side with a recomp value."""
    with db.batch() as batch:
        batch.set_orig(100, name="Test", test=None)
        batch.set_recomp(200, name="Hello", test=123)
        batch.match(100, 200)

    assert db.get_by_recomp(200).get("test") == 123


@pytest.mark.xfail(reason="Known limitation.")
def test_batch_match_create(db):
    """Matching requires either the orig or recomp entity to exist. It does not create entities."""
    with db.batch() as batch:
        batch.match(100, 200)

    assert db.get_by_orig(100).recomp_addr == 200


def test_batch_commit_twice(db):
    """Calling commit() clears the pending updates.
    Calling commit() again without adding new changes will not alter the database."""
    batch = db.batch()
    batch.set_orig(100, name="Test")

    with patch("reccmp.isledecomp.compare.db.EntityDb.bulk_orig_insert") as mock:
        batch.commit()
        batch.commit()
        mock.assert_called_once()

    with patch("reccmp.isledecomp.compare.db.EntityDb.bulk_orig_insert") as mock:
        batch.commit()
        mock.assert_not_called()


def test_batch_cannot_alter_matched(db):
    """batch.match() will not change an entity that is already matched."""

    # Set up the match
    with db.batch() as batch:
        batch.set_recomp(200, name="Test")
        batch.match(100, 200)

    # Confirm it is there
    assert db.get_by_orig(100).recomp_addr == 200

    # Try to change recomp=200 to match orig=101
    with db.batch() as batch:
        batch.match(101, 200)

    # Should not change it
    assert db.get_by_recomp(200).orig_addr == 100


def test_batch_change_staged_match(db):
    """You can change an unsaved match by calling match() again on the same orig addr."""
    with db.batch() as batch:
        batch.set_recomp(200, name="Hello")
        batch.set_recomp(201, name="Test")
        batch.match(100, 200)
        batch.match(100, 201)

    assert db.get_by_orig(100).recomp_addr == 201
    assert db.get_by_recomp(200).orig_addr is None


def test_batch_match_repeat_recomp_addr(db):
    """Calling match() with the same recomp addr should work the same as the orig addr case.
    Discard the first match in favor of the new one."""
    with db.batch() as batch:
        batch.set_recomp(200, name="Hello")
        batch.set_recomp(201, name="Test")
        batch.match(100, 200)
        batch.match(101, 200)

    assert db.get_by_recomp(200).orig_addr == 101
    assert db.get_by_orig(100) is None


def test_batch_exception_uncaught(db):
    """When using batch context manager, an uncaught exception should clear the staged changes."""
    try:
        with db.batch() as batch:
            batch.set_orig(100, name="Test")
            batch.set_recomp(200, test=123)
            batch.match(100, 200)
            _ = 1 / 0
    except ZeroDivisionError:
        pass

    assert db.get_by_orig(100) is None
    assert db.get_by_orig(200) is None


def test_batch_exception_caught(db):
    """If the exception is caught, allow the batch to go through."""
    with db.batch() as batch:
        batch.set_orig(100, name="Test")
        batch.set_recomp(200, test=123)
        batch.match(100, 200)
        try:
            _ = 1 / 0
        except ZeroDivisionError:
            pass

    assert db.get_by_orig(100) is not None
    assert db.get_by_recomp(200) is not None


def test_batch_sqlite_exception(db):
    """Should rollback if an exception occurs during the commit."""

    # Not using batch context for clarity
    batch = db.batch()
    batch.set_orig(100, name="Test")
    batch.set_recomp(200, test=123)

    # Insert bad data that will cause a binding error
    batch.match(100, ("bogus",))

    with pytest.raises(sqlite3.Error):
        batch.commit()

    # Should rollback everything
    assert db.get_by_orig(100) is None
    assert db.get_by_recomp(200) is None


def test_batch_sqlite_exception_insert_only(db):
    """Should rollback even if we don't start the explicit transaction in match()"""
    batch = db.batch()
    batch.insert_orig(100, name="Test")
    batch.insert_orig(("bogus",), name="Test")

    with pytest.raises(sqlite3.Error):
        batch.commit()

    assert db.get_by_orig(100) is None
