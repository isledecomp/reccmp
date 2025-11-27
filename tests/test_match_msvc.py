"""Tests MSVC-specific match strategies"""

from unittest.mock import Mock, ANY
import pytest
from reccmp.isledecomp.types import EntityType, ImageId
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.compare.match_msvc import (
    match_functions,
    match_static_variables,
    match_strings,
    match_symbols,
    match_variables,
    match_vtables,
    match_ref,
)
from reccmp.isledecomp.compare.event import ReccmpEvent, ReccmpReportProtocol


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


@pytest.fixture(name="report")
def fixture_report_mock() -> ReccmpReportProtocol:
    return Mock(spec=ReccmpReportProtocol)


#### match_symbols ####


def test_match_symbols(db):
    """Should combine entities with the same symbol"""
    with db.batch() as batch:
        batch.set_orig(123, symbol="hello")
        batch.set_recomp(555, symbol="hello")

    match_symbols(db)

    assert db.get_by_orig(123).recomp_addr == 555
    assert db.get_by_recomp(555).orig_addr == 123

    # Should combine entities
    assert db.count() == 1


def test_match_symbols_no_match(db):
    """Should not affect entities with no symbol or no matching symbol."""
    with db.batch() as batch:
        batch.set_orig(123)
        batch.set_recomp(555, symbol="hello")

    match_symbols(db)

    assert db.get_by_orig(123).recomp_addr is None
    assert db.get_by_recomp(555).orig_addr is None
    assert db.count() == 2


def test_match_symbols_no_match_report(db, report):
    """Should report if we cannot match a symbol on the orig side."""
    with db.batch() as batch:
        batch.set_orig(123, symbol="test")

    match_symbols(db, report)

    report.assert_called_with(ReccmpEvent.NO_MATCH, 123, msg=ANY)


def test_match_symbols_stable_match_order(db):
    """Match in ascending address order on both sides for duplicate symbols."""
    with db.batch() as batch:
        # Descending order
        batch.set_orig(200, symbol="test")
        batch.set_orig(100, symbol="test")
        batch.set_recomp(555, symbol="test")
        batch.set_recomp(333, symbol="test")

    match_symbols(db)

    assert db.get_by_orig(100).recomp_addr == 333
    assert db.get_by_orig(200).recomp_addr == 555


def test_match_symbols_recomp_not_unique(db, report):
    """Alert when symbol match is non-unique on the recomp side."""
    with db.batch() as batch:
        batch.set_orig(123, symbol="hello")
        batch.set_recomp(555, symbol="hello")
        batch.set_recomp(222, symbol="hello")

    match_symbols(db, report)

    # Should match first occurrence.
    assert db.get_by_orig(123).recomp_addr == 222

    # Report non-unique match for orig_addr 123
    report.assert_called_with(ReccmpEvent.NON_UNIQUE_SYMBOL, 123, msg=ANY)


def test_match_symbols_truncate_255(db):
    """MSVC 4.2 truncates symbols to 255 characters in the PDB.
    Match entities where the symbols are equal up to the 255th character."""
    long_name = "x" * 255
    with db.batch() as batch:
        batch.set_orig(123, symbol=long_name + "y")
        batch.set_recomp(555, symbol=long_name + "z")

    match_symbols(db, truncate=True)

    assert db.get_by_orig(123).recomp_addr == 555
    assert db.get_by_recomp(555).orig_addr == 123


def test_match_symbols_no_truncate(db):
    """Should recognize these as distinct symbols if truncate=False"""
    long_name = "x" * 255
    with db.batch() as batch:
        batch.set_orig(123, symbol=long_name + "y")
        batch.set_recomp(555, symbol=long_name + "z")

    match_symbols(db, truncate=False)

    assert db.get_by_orig(123).recomp_addr is None
    assert db.get_by_recomp(555).orig_addr is None


#### match_functions ####


def test_match_functions(db):
    """Simple match by name and type"""
    with db.batch() as batch:
        batch.set_orig(123, name="hello", type=EntityType.FUNCTION)
        batch.set_recomp(555, name="hello", type=EntityType.FUNCTION)

    match_functions(db)

    assert db.get_by_orig(123).recomp_addr == 555
    assert db.get_by_recomp(555).orig_addr == 123

    # Should combine entities
    assert db.count() == 1


def test_match_functions_no_match(db):
    """Skip entities with no match"""
    with db.batch() as batch:
        batch.set_orig(123, name="hello", type=EntityType.FUNCTION)
        batch.set_recomp(555, name="test", type=EntityType.FUNCTION)

    match_functions(db)

    assert db.get_by_orig(123).recomp_addr is None
    assert db.get_by_recomp(555).orig_addr is None
    assert db.count() == 2


def test_match_functions_no_match_report(db, report):
    """Should report if we cannot match a name on the orig side."""
    with db.batch() as batch:
        batch.set_orig(123, name="test", type=EntityType.FUNCTION)

    match_functions(db, report)

    report.assert_called_with(ReccmpEvent.NO_MATCH, 123, msg=ANY)


def test_match_function_stable_order(db):
    """If name is not unique, match according to orig and recomp address order.
    i.e. insertion order does not matter"""
    with db.batch() as batch:
        # Descending order
        batch.set_orig(101, name="hello", type=EntityType.FUNCTION)
        batch.set_orig(100, name="hello", type=EntityType.FUNCTION)
        batch.set_recomp(501, name="hello", type=EntityType.FUNCTION)
        batch.set_recomp(500, name="hello", type=EntityType.FUNCTION)

    match_functions(db)

    assert db.get_by_orig(100).recomp_addr == 500
    assert db.get_by_orig(101).recomp_addr == 501


def test_match_functions_type_null(db):
    """Will allow a function match if the recomp side has type=null"""
    with db.batch() as batch:
        batch.set_orig(123, name="hello", type=EntityType.FUNCTION)
        batch.set_recomp(555, name="hello")

    match_functions(db)

    assert db.get_by_orig(123).recomp_addr == 555
    assert db.get_by_recomp(555).orig_addr == 123
    assert db.count() == 1


def test_match_functions_ambiguous(db, report):
    """Report if a name match had multiple options.
    If there is only one option left, but previous matches were ambiguous, report it anyway.
    """
    with db.batch() as batch:
        batch.set_orig(100, name="hello", type=EntityType.FUNCTION)
        batch.set_orig(101, name="hello", type=EntityType.FUNCTION)
        batch.set_recomp(500, name="hello", type=EntityType.FUNCTION)
        batch.set_recomp(501, name="hello", type=EntityType.FUNCTION)

    match_functions(db, report)

    # Report for both ambiguous matches
    report.assert_any_call(ReccmpEvent.AMBIGUOUS_MATCH, 100, msg=ANY)
    report.assert_any_call(ReccmpEvent.AMBIGUOUS_MATCH, 101, msg=ANY)

    # Should match regardless
    assert db.count() == 2


def test_match_functions_ignore_already_matched(db, report):
    """If the name is non-unique but there is only one option available to match
    (i.e. if previous entities were matched by line number)
    do not report an ambiguous match."""
    with db.batch() as batch:
        batch.set_orig(101, name="hello", type=EntityType.FUNCTION)
        batch.set_recomp(500, name="hello", type=EntityType.FUNCTION)
        batch.set_recomp(501, name="hello", type=EntityType.FUNCTION)
        # Match these addrs before calling match_functions()
        batch.match(100, 500)

    # 1 matched, 2 unmatched
    assert db.count() == 3

    match_functions(db, report)

    # Do not report
    report.assert_not_called()

    # Should combine the two unmatched entities
    assert db.get_by_recomp(501).orig_addr == 101
    assert db.count() == 2


def test_match_function_names_truncate_255(db):
    """MSVC 4.2 truncates names to 255 characters in the PDB.
    Match function entities where the names are are equal up to the 255th character."""
    long_name = "x" * 255
    with db.batch() as batch:
        batch.set_orig(123, name=long_name + "y", type=EntityType.FUNCTION)
        batch.set_recomp(555, name=long_name + "z", type=EntityType.FUNCTION)

    match_functions(db, truncate=True)

    assert db.get_by_orig(123).recomp_addr == 555
    assert db.get_by_recomp(555).orig_addr == 123


def test_match_function_names_no_truncate(db):
    """Should recognize these as distinct names if truncate=False"""
    long_name = "x" * 255
    with db.batch() as batch:
        batch.set_orig(123, name=long_name + "y", type=EntityType.FUNCTION)
        batch.set_recomp(555, name=long_name + "z", type=EntityType.FUNCTION)

    match_functions(db, truncate=False)

    assert db.get_by_orig(123).recomp_addr is None
    assert db.get_by_recomp(555).orig_addr is None


#### match_vtables ####


def test_match_vtables(db):
    """Matching with the specific requirements on attributes for orig and recomp entities"""
    with db.batch() as batch:
        # Orig has class name and type
        batch.set_orig(100, name="Pizza", type=EntityType.VTABLE)
        # Recomp has full vtable name and type
        batch.set_recomp(200, name="Pizza::`vftable'", type=EntityType.VTABLE)

    match_vtables(db)

    assert db.get_by_orig(100).recomp_addr == 200
    assert db.count() == 1


def test_match_vtables_no_match_recomp_name(db):
    """Recomp entity name must be in a specific format"""
    with db.batch() as batch:
        batch.set_orig(100, name="Pizza", type=EntityType.VTABLE)
        batch.set_recomp(200, name="Pizza", type=EntityType.VTABLE)

    match_vtables(db)

    assert db.get_by_orig(100).recomp_addr is None


def test_match_vtables_no_match_recomp_type(db):
    """Recomp entity must have type=EntityType.VTABLE"""
    with db.batch() as batch:
        batch.set_orig(100, name="Pizza", type=EntityType.VTABLE)
        batch.set_recomp(200, name="Pizza::`vftable'")

    match_vtables(db)

    assert db.get_by_orig(100).recomp_addr is None


def test_match_vtables_no_match_orig_type(db):
    """Orig entity must have type=EntityType.VTABLE"""
    with db.batch() as batch:
        batch.set_orig(100, name="Pizza")
        batch.set_recomp(200, name="Pizza::`vftable'", type=EntityType.VTABLE)

    match_vtables(db)

    assert db.get_by_orig(100).recomp_addr is None


def test_match_vtables_no_match_report(db, report):
    """Report a failure to match a vtable from the orig side."""
    with db.batch() as batch:
        batch.set_orig(100, name="Pizza", type=EntityType.VTABLE)

    match_vtables(db, report)

    report.assert_called_with(ReccmpEvent.NO_MATCH, 100, msg=ANY)


def test_match_vtables_base_class(db):
    """Match a vtable with a base class"""
    with db.batch() as batch:
        batch.set_orig(100, name="Pizza", type=EntityType.VTABLE, base_class="Lunch")
        batch.set_recomp(
            200, name="Pizza::`vftable'{for `Lunch'}", type=EntityType.VTABLE
        )

    match_vtables(db)

    assert db.get_by_orig(100).recomp_addr == 200


def test_match_vtables_base_class_orig_none(db):
    """Do not match a multiple-inheritance vtable if the base class is not specified on the orig entity."""
    with db.batch() as batch:
        batch.set_orig(100, name="Pizza", type=EntityType.VTABLE)
        batch.set_recomp(
            200, name="Pizza::`vftable'{for `Lunch'}", type=EntityType.VTABLE
        )

    match_vtables(db)

    assert db.get_by_orig(100).recomp_addr is None


def test_match_vtables_base_class_same_as_derived(db):
    """Matching a vtable with the same base class and derived class.
    The base_class attribute is set on the orig entity."""
    with db.batch() as batch:
        batch.set_orig(100, name="Pizza", type=EntityType.VTABLE, base_class="Pizza")
        batch.set_recomp(
            200, name="Pizza::`vftable'{for `Pizza'}", type=EntityType.VTABLE
        )

    match_vtables(db)

    assert db.get_by_orig(100).recomp_addr == 200


def test_match_vtables_base_class_same_as_derived_orig_none(db):
    """If orig does not have the base_class attribute set, we can still match if
    the recomp vtable has the same base and derived class."""
    with db.batch() as batch:
        batch.set_orig(100, name="Pizza", type=EntityType.VTABLE)
        batch.set_recomp(
            200, name="Pizza::`vftable'{for `Pizza'}", type=EntityType.VTABLE
        )

    match_vtables(db)

    assert db.get_by_orig(100).recomp_addr == 200


def test_match_vtables_incompatible_base_class(db):
    """If the orig entity has a base_class, do not match with a recomp vtable that does not use multiple-inheritance."""
    with db.batch() as batch:
        batch.set_orig(100, name="Pizza", type=EntityType.VTABLE, base_class="Lunch")
        batch.set_recomp(200, name="Pizza::`vftable'", type=EntityType.VTABLE)

    match_vtables(db)

    assert db.get_by_orig(100).recomp_addr is None


#### match_static_variables ####


def test_match_static_var(db):
    """Match a static variable with all requirements satisfied."""
    with db.batch() as batch:
        # Orig entity function with symbol
        batch.set_orig(200, symbol="?Tick@IsleApp@@QAEXH@Z", type=EntityType.FUNCTION)
        # Static variable with symbol
        batch.set_recomp(500, symbol="?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA")
        # Orig entity with variable name and link to orig function addr
        batch.set_orig(
            600,
            name="g_startupDelay",
            parent_function=200,
            static_var=True,
            type=EntityType.DATA,
        )

    match_static_variables(db)

    assert db.get_by_orig(600).recomp_addr == 500


def test_match_static_var_no_parent_function(db):
    """Cannot match static variable without a reference to its parent function"""
    with db.batch() as batch:
        batch.set_orig(200, symbol="?Tick@IsleApp@@QAEXH@Z", type=EntityType.FUNCTION)
        batch.set_recomp(500, symbol="?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA")
        # No parent function
        batch.set_orig(
            600,
            name="g_startupDelay",
            static_var=True,
            type=EntityType.DATA,
        )

    match_static_variables(db)

    assert db.get_by_orig(600).recomp_addr is None


def test_match_static_var_static_false(db):
    """Cannot match static variable unless the static_var attribute is True"""
    with db.batch() as batch:
        batch.set_orig(200, symbol="?Tick@IsleApp@@QAEXH@Z", type=EntityType.FUNCTION)
        batch.set_recomp(500, symbol="?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA")
        # static_var is not set
        batch.set_orig(
            600,
            name="g_startupDelay",
            parent_function=200,
            type=EntityType.DATA,
        )

    match_static_variables(db)

    assert db.get_by_orig(600).recomp_addr is None


def test_match_static_var_no_symbol_function(db):
    """Cannot match static variable if the parent function has no symbol"""
    with db.batch() as batch:
        # No symbol on parent function
        batch.set_orig(200, type=EntityType.FUNCTION)
        batch.set_recomp(500, symbol="?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA")
        batch.set_orig(
            600,
            name="g_startupDelay",
            parent_function=200,
            static_var=True,
            type=EntityType.DATA,
        )

    match_static_variables(db)

    assert db.get_by_orig(600).recomp_addr is None


def test_match_static_var_no_symbol_variable(db):
    """Cannot match static variable without a symbol."""
    with db.batch() as batch:
        batch.set_orig(200, symbol="?Tick@IsleApp@@QAEXH@Z", type=EntityType.FUNCTION)
        # No symbol on variable
        batch.set_recomp(500, name="g_startupDelay")
        batch.set_orig(
            600,
            name="g_startupDelay",
            parent_function=200,
            static_var=True,
            type=EntityType.DATA,
        )

    match_static_variables(db)

    assert db.get_by_orig(600).recomp_addr is None


def test_match_static_var_no_match_report(db, report):
    """Report match failure for any orig entities with static_var=True"""
    with db.batch() as batch:
        batch.set_orig(600, name="test", static_var=True, type=EntityType.DATA)

    match_static_variables(db, report)

    report.assert_called_with(ReccmpEvent.NO_MATCH, 600, msg=ANY)


#### match_variables ####


def test_match_variables(db):
    """Simple match by name and type"""
    with db.batch() as batch:
        batch.set_orig(123, name="hello", type=EntityType.DATA)
        batch.set_recomp(555, name="hello", type=EntityType.DATA)

    match_variables(db)

    assert db.get_by_orig(123).recomp_addr == 555
    assert db.get_by_recomp(555).orig_addr == 123

    # Should combine entities
    assert db.count() == 1


def test_match_variables_no_match(db):
    """Skip entities with no match"""
    with db.batch() as batch:
        batch.set_orig(123, name="hello", type=EntityType.DATA)
        batch.set_recomp(555, name="test", type=EntityType.DATA)

    match_variables(db)

    assert db.get_by_orig(123).recomp_addr is None
    assert db.get_by_recomp(555).orig_addr is None
    assert db.count() == 2


def test_match_variables_no_match_report(db, report):
    """Should report if we cannot match a name on the orig side."""
    with db.batch() as batch:
        batch.set_orig(123, name="test", type=EntityType.DATA)

    match_variables(db, report)

    report.assert_called_with(ReccmpEvent.NO_MATCH, 123, msg=ANY)


def test_match_variables_type_null(db):
    """Will allow a variable match if the recomp side has type=null"""
    with db.batch() as batch:
        batch.set_orig(123, name="hello", type=EntityType.DATA)
        batch.set_recomp(555, name="hello")

    match_variables(db)

    assert db.get_by_orig(123).recomp_addr == 555
    assert db.get_by_recomp(555).orig_addr == 123
    assert db.count() == 1


#### match_strings ####


def test_match_strings(db):
    with db.batch() as batch:
        batch.set_orig(123, name="hello", type=EntityType.STRING)
        batch.set_recomp(555, name="hello", type=EntityType.STRING)

    match_strings(db)

    assert db.get_by_orig(123).recomp_addr == 555
    assert db.get_by_recomp(555).orig_addr == 123

    # Should combine entities
    assert db.count() == 1


def test_match_strings_no_match(db):
    """Skip strings with no match"""
    with db.batch() as batch:
        batch.set_orig(123, name="hello", type=EntityType.STRING)
        batch.set_recomp(555, name="test", type=EntityType.STRING)

    match_strings(db)

    assert db.get_by_orig(123).recomp_addr is None
    assert db.get_by_recomp(555).orig_addr is None
    assert db.count() == 2


def test_match_strings_type_required(db):
    """Do not match if one side is missing the type.
    This is a concern because we use the name attribute for the string's text."""
    with db.batch() as batch:
        batch.set_orig(100, name="hello", type=EntityType.STRING)
        batch.set_orig(200, name="test")
        batch.set_recomp(500, name="hello")
        batch.set_recomp(600, name="test", type=EntityType.STRING)

    match_strings(db)

    assert db.get_by_orig(100).recomp_addr is None
    assert db.get_by_orig(200).recomp_addr is None


def test_match_strings_no_match_report(db, report):
    """Should report if we cannot match a string on the orig side.
    However: only alert if the string is 'verified' by user input,
    a symbol in the PDB, or some (future) heuristic."""
    with db.batch() as batch:
        batch.set_orig(123, name="test", type=EntityType.STRING)

    match_strings(db, report)

    # Not verified: no alert for failed match
    report.assert_not_called()

    # Should alert after we mark the string as verified
    with db.batch() as batch:
        batch.set_orig(123, verified=True)

    match_strings(db, report)
    report.assert_called_with(ReccmpEvent.NO_MATCH, 123, msg=ANY)


def test_match_strings_duplicates(db, report):
    """Binaries that do not de-dupe string should match duplicates by address order."""
    with db.batch() as batch:
        batch.set_orig(100, name="hello", type=EntityType.STRING)
        batch.set_orig(200, name="hello", type=EntityType.STRING)
        batch.set_orig(300, name="hello", type=EntityType.STRING)
        batch.set_recomp(500, name="hello", type=EntityType.STRING)
        batch.set_recomp(600, name="hello", type=EntityType.STRING)
        batch.set_recomp(700, name="hello", type=EntityType.STRING)

    match_strings(db, report)

    assert db.get_by_orig(100).recomp_addr == 500
    assert db.get_by_orig(200).recomp_addr == 600
    assert db.get_by_orig(300).recomp_addr == 700
    assert db.count() == 3

    # Do not alert for duplicate string matches.
    report.assert_not_called()


def test_match_strings_stable_order(db):
    """Duplicates are matched by address order, not db insertion order."""
    with db.batch() as batch:
        # Descending order
        batch.set_orig(300, name="hello", type=EntityType.STRING)
        batch.set_orig(200, name="hello", type=EntityType.STRING)
        batch.set_orig(100, name="hello", type=EntityType.STRING)
        batch.set_recomp(700, name="hello", type=EntityType.STRING)
        batch.set_recomp(600, name="hello", type=EntityType.STRING)
        batch.set_recomp(500, name="hello", type=EntityType.STRING)

    match_strings(db)

    assert db.get_by_orig(100).recomp_addr == 500
    assert db.get_by_orig(200).recomp_addr == 600
    assert db.get_by_orig(300).recomp_addr == 700


def test_match_ref(db):
    """Match child entities that refer to the same matched parent entity, regardless of type."""
    with db.batch() as batch:
        batch.set_orig(100)
        batch.set_recomp(500)
        batch.match(100, 500)

        batch.set(ImageId.ORIG, 200)
        batch.set_ref(ImageId.ORIG, 200, ref=100)

        batch.set(ImageId.RECOMP, 600)
        batch.set_ref(ImageId.RECOMP, 600, ref=500)

    match_ref(db)

    assert db.get_by_orig(200).recomp_addr == 600
    assert db.get_by_recomp(600).orig_addr == 200


def test_match_ref_chained(db):
    """Match any child entities that refer to other child entities,
    provided we have a matched parent at the end of the chain."""
    with db.batch() as batch:
        batch.set_orig(100)
        batch.set_recomp(500)
        batch.match(100, 500)

        # First level
        batch.set(ImageId.ORIG, 200)
        batch.set_ref(ImageId.ORIG, 200, ref=100)

        batch.set(ImageId.RECOMP, 600)
        batch.set_ref(ImageId.RECOMP, 600, ref=500)

        # Second level
        batch.set(ImageId.ORIG, 300)
        batch.set_ref(ImageId.ORIG, 300, ref=200)

        batch.set(ImageId.RECOMP, 700)
        batch.set_ref(ImageId.RECOMP, 700, ref=600)

    match_ref(db)

    assert db.get_by_orig(200).recomp_addr == 600
    assert db.get_by_recomp(600).orig_addr == 200

    assert db.get_by_orig(300).recomp_addr == 700
    assert db.get_by_recomp(700).orig_addr == 300


def test_match_ref_parent_not_matched(db):
    """Don't match child entities if the parent is not matched."""
    with db.batch() as batch:
        batch.set_orig(100)
        batch.set_recomp(500)
        # Don't match parent entity.

        batch.set(ImageId.ORIG, 200)
        batch.set_ref(ImageId.ORIG, 200, ref=100)

        batch.set(ImageId.RECOMP, 600)
        batch.set_ref(ImageId.RECOMP, 600, ref=500)

    match_ref(db)

    # Child entities unchanged.
    assert db.get_by_orig(200).recomp_addr is None
    assert db.get_by_recomp(600).orig_addr is None


def test_match_ref_expected_order(db):
    """If there is more than one child entity that points to the same matched parent,
    match according to child address order."""
    with db.batch() as batch:
        batch.set_orig(100)
        batch.set_recomp(500)
        batch.match(100, 500)

        # Orig thunks
        for addr in (200, 201, 202):
            batch.set(ImageId.ORIG, addr)
            batch.set_ref(ImageId.ORIG, addr, ref=100)

        # Recomp thunks (reverse order to verify expected match)
        for addr in (602, 601, 600):
            batch.set(ImageId.RECOMP, addr)
            batch.set_ref(ImageId.RECOMP, addr, ref=500)

    match_ref(db)

    assert db.get_by_orig(200).recomp_addr == 600
    assert db.get_by_orig(201).recomp_addr == 601
    assert db.get_by_orig(202).recomp_addr == 602


def test_match_ref_include_vtordisp(db):
    """If a displacement value is specified for the child entity (vtordisp)
    use it when matching the parent."""
    with db.batch() as batch:
        batch.set_orig(100)
        batch.set_recomp(500)
        batch.match(100, 500)

        batch.set(ImageId.ORIG, 200)
        batch.set(ImageId.ORIG, 201)
        batch.set_ref(ImageId.ORIG, 200, ref=100)
        batch.set_ref(ImageId.ORIG, 201, ref=100, displacement=(-4, 0))

        batch.set(ImageId.RECOMP, 600)
        batch.set(ImageId.RECOMP, 601)
        batch.set_ref(ImageId.RECOMP, 600, ref=500)
        batch.set_ref(ImageId.RECOMP, 601, ref=500, displacement=(-4, 0))

    match_ref(db)

    # Match thunks and vtordisp separately.
    assert db.get_by_orig(200).recomp_addr == 600
    assert db.get_by_orig(201).recomp_addr == 601


def test_match_ref_include_vtordisp_order(db):
    """For child entities with duplicate parent and displacement values, match
    by child address order.
    NOTE: It may not be possible for MSVC to duplicate vtordisps in this way."""
    with db.batch() as batch:
        batch.set_orig(100)
        batch.set_recomp(500)
        batch.match(100, 500)

        # Orig thunks
        for addr in (200, 201, 202):
            batch.set(ImageId.ORIG, addr)
            batch.set_ref(ImageId.ORIG, addr, ref=100, displacement=(-4, 0))

        # Recomp thunks (reverse order to verify expected match)
        for addr in (602, 601, 600):
            batch.set(ImageId.RECOMP, addr)
            batch.set_ref(ImageId.RECOMP, addr, ref=500, displacement=(-4, 0))

    match_ref(db)

    assert db.get_by_orig(200).recomp_addr == 600
    assert db.get_by_orig(201).recomp_addr == 601
    assert db.get_by_orig(202).recomp_addr == 602
