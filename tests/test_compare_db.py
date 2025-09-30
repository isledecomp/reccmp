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


def test_db_all_order(db):
    """get_all() returns matched and unmatched entities. The order should be:
    1. Matched and unmatched entities by orig_addr, ascending.
    2. Unmatched entities with only a recomp_addr. Order by recomp_addr, ascending."""
    with db.batch() as batch:
        for addr in (600, 500, 300, 200):
            batch.set_recomp(addr)

        for addr in (400, 300, 200, 100):
            batch.set_orig(addr)

        batch.match(200, 200)
        batch.match(300, 300)

    addrs = [(e.orig_addr, e.recomp_addr) for e in db.get_all()]

    assert addrs == [
        (100, None),
        (200, 200),
        (300, 300),
        (400, None),
        (None, 500),
        (None, 600),
    ]


def test_get_by_exact(db):
    """get_by_orig and get_by_recomp have two parameters: the address and the 'exact' option.
    If exact=False, we return the entity at the address OR one at the preceding address if it exists.
    """

    with db.batch() as batch:
        batch.set_orig(100)
        batch.set_recomp(100)

    # If there is an exact addr match, return the entity.
    assert db.get_by_orig(100) is not None
    assert db.get_by_orig(100, exact=True) is not None
    assert db.get_by_orig(100, exact=False) is not None
    assert db.get_by_recomp(100) is not None
    assert db.get_by_recomp(100, exact=True) is not None
    assert db.get_by_recomp(100, exact=False) is not None

    # If there is no exact match, return None.
    assert db.get_by_orig(200) is None
    assert db.get_by_orig(200, exact=True) is None
    assert db.get_by_recomp(200) is None
    assert db.get_by_recomp(200, exact=True) is None

    # Return the preceding entity if exact=False.
    assert db.get_by_orig(200, exact=False) is not None
    assert db.get_by_recomp(200, exact=False) is not None

    # Should only return the preceding entity if one exists.
    assert db.get_by_orig(50, exact=False) is None
    assert db.get_by_recomp(50, exact=False) is None


def test_get_by_exact_keyword(db: EntityDb):
    """For get_by_orig and get_by_recomp, the 'exact' keyword must be used to set its value."""

    # Should fail if called without the 'exact' keyword.
    # Disable mypy checking for these calls because we've intentionally created a typing error.
    with pytest.raises(TypeError):
        db.get_by_orig(100, False)  # type: ignore

    with pytest.raises(TypeError):
        db.get_by_orig(100, True)  # type: ignore

    with pytest.raises(TypeError):
        db.get_by_recomp(100, True)  # type: ignore

    with pytest.raises(TypeError):
        db.get_by_recomp(100, False)  # type: ignore

    # Succeeds with 'exact' keyword or if it the parameter is omitted.
    db.get_by_orig(100)
    db.get_by_orig(100, exact=False)
    db.get_by_orig(100, exact=True)
    db.get_by_recomp(100)
    db.get_by_recomp(100, exact=False)
    db.get_by_recomp(100, exact=True)


#### Testing new batch API ####


def test_batch(db):
    """Demonstrate batch with context manager"""
    with db.batch() as batch:
        batch.set_orig(100, name="Hello")
        batch.set_recomp(200, name="Test")

    assert db.get_by_orig(100).name == "Hello"
    assert db.get_by_recomp(200).name == "Test"


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


def test_batch_match_repeat_orig_addr(db):
    """We expect a batch of matches to be limited to the results of a particular query.
    As such, each orig and recomp address should appear only once. If either address is repeated
    and would collide with a previous staged match, ignore the new one."""
    with db.batch() as batch:
        batch.set_recomp(200, name="Hello")
        batch.set_recomp(201, name="Test")
        batch.match(100, 200)
        batch.match(100, 201)

    assert db.get_by_orig(100).recomp_addr == 200
    assert db.get_by_recomp(201).orig_addr is None


def test_batch_match_repeat_recomp_addr(db):
    """Same as the previous test, except that we are repeating the recomp addr instead of orig."""
    with db.batch() as batch:
        batch.set_recomp(200, name="Hello")
        batch.set_recomp(201, name="Test")
        batch.match(100, 200)
        batch.match(101, 200)

    assert db.get_by_recomp(200).orig_addr == 100
    assert db.get_by_orig(101) is None


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
