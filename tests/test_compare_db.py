"""Testing compare database behavior, particularly matching"""

import pytest
from reccmp.isledecomp.compare.db import CompareDb


@pytest.fixture(name="db")
def fixture_db():
    return CompareDb()


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
