"""Tests MSVC-specific match strategies"""

# pylint:disable=too-many-lines

from typing import TypeVar
from unittest.mock import Mock, ANY, patch
import pytest
from reccmp.cvdump.types import CvdumpTypesParser
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb
from reccmp.compare.match_msvc import (
    match_functions,
    match_static_variables,
    match_strings,
    match_symbols,
    match_variables,
    match_vtables,
    match_ref,
    match_imports,
)
from reccmp.compare.event import ReccmpEvent, ReccmpReportProtocol


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


@pytest.fixture(name="types")
def fixture_types() -> CvdumpTypesParser:
    return CvdumpTypesParser()


@pytest.fixture(name="report")
def fixture_report_mock() -> ReccmpReportProtocol:
    return Mock(spec=ReccmpReportProtocol)


T = TypeVar("T")


def assert_defined(value: T | None) -> T:
    """Helper for null-safe one-liners"""
    assert value is not None
    return value


#### match_symbols ####


def test_match_symbols(db: EntityDb):
    """Should combine entities with the same symbol"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, symbol="hello")
        batch.set(ImageId.RECOMP, 555, symbol="hello")

    match_symbols(db)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr == 555
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr == 123

    # Should combine entities
    assert db.count() == 1


def test_match_symbols_no_match(db: EntityDb):
    """Should not affect entities with no symbol or no matching symbol."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123)
        batch.set(ImageId.RECOMP, 555, symbol="hello")

    match_symbols(db)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr is None
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr is None
    assert db.count() == 2


def test_match_symbols_no_match_report(db: EntityDb, report: Mock):
    """Should report if we cannot match a symbol on the orig side."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, symbol="test")

    match_symbols(db, report)

    report.assert_called_with(ReccmpEvent.NO_MATCH, 123, msg=ANY)


def test_match_symbols_stable_match_order(db: EntityDb):
    """Match in ascending address order on both sides for duplicate symbols."""
    with db.batch() as batch:
        # Descending order
        batch.set(ImageId.ORIG, 200, symbol="test")
        batch.set(ImageId.ORIG, 100, symbol="test")
        batch.set(ImageId.RECOMP, 555, symbol="test")
        batch.set(ImageId.RECOMP, 333, symbol="test")

    match_symbols(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr == 333
    assert assert_defined(db.get(ImageId.ORIG, 200)).recomp_addr == 555


def test_match_symbols_recomp_not_unique(db: EntityDb, report: Mock):
    """Alert when symbol match is non-unique on the recomp side."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, symbol="hello")
        batch.set(ImageId.RECOMP, 555, symbol="hello")
        batch.set(ImageId.RECOMP, 222, symbol="hello")

    match_symbols(db, report)

    # Should match first occurrence.
    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr == 222

    # Report non-unique match for orig_addr 123
    report.assert_called_with(ReccmpEvent.NON_UNIQUE_SYMBOL, 123, msg=ANY)


def test_match_symbols_truncate_255(db: EntityDb):
    """MSVC 4.2 truncates symbols to 255 characters in the PDB.
    Match entities where the symbols are equal up to the 255th character."""
    long_name = "x" * 255
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, symbol=long_name + "y")
        batch.set(ImageId.RECOMP, 555, symbol=long_name + "z")

    match_symbols(db, truncate=True)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr == 555
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr == 123


def test_match_symbols_no_truncate(db: EntityDb):
    """Should recognize these as distinct symbols if truncate=False"""
    long_name = "x" * 255
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, symbol=long_name + "y")
        batch.set(ImageId.RECOMP, 555, symbol=long_name + "z")

    match_symbols(db, truncate=False)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr is None
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr is None


#### match_functions ####


def test_match_functions(db: EntityDb):
    """Simple match by name and type"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="hello", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 555, name="hello", type=EntityType.FUNCTION)

    match_functions(db)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr == 555
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr == 123

    # Should combine entities
    assert db.count() == 1


def test_match_functions_no_match(db: EntityDb):
    """Skip entities with no match"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="hello", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 555, name="test", type=EntityType.FUNCTION)

    match_functions(db)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr is None
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr is None
    assert db.count() == 2


def test_match_functions_no_match_report(db: EntityDb, report: Mock):
    """Should report if we cannot match a name on the orig side."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="test", type=EntityType.FUNCTION)

    match_functions(db, report)

    report.assert_called_with(ReccmpEvent.NO_MATCH, 123, msg=ANY)


def test_match_function_stable_order(db: EntityDb):
    """If name is not unique, match according to orig and recomp address order.
    i.e. insertion order does not matter"""
    with db.batch() as batch:
        # Descending order
        batch.set(ImageId.ORIG, 101, name="hello", type=EntityType.FUNCTION)
        batch.set(ImageId.ORIG, 100, name="hello", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 501, name="hello", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 500, name="hello", type=EntityType.FUNCTION)

    match_functions(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr == 500
    assert assert_defined(db.get(ImageId.ORIG, 101)).recomp_addr == 501


def test_match_functions_type_null(db: EntityDb):
    """Will allow a function match if the recomp side has type=null"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="hello", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 555, name="hello")

    match_functions(db)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr == 555
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr == 123
    assert db.count() == 1


def test_match_functions_ambiguous(db: EntityDb, report: Mock):
    """Report if a name match had multiple options.
    If there is only one option left, but previous matches were ambiguous, report it anyway.
    """
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, name="hello", type=EntityType.FUNCTION)
        batch.set(ImageId.ORIG, 101, name="hello", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 500, name="hello", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 501, name="hello", type=EntityType.FUNCTION)

    match_functions(db, report)

    # Report for both ambiguous matches
    report.assert_any_call(ReccmpEvent.AMBIGUOUS_MATCH, 100, msg=ANY)
    report.assert_any_call(ReccmpEvent.AMBIGUOUS_MATCH, 101, msg=ANY)

    # Should match regardless
    assert db.count() == 2


def test_match_functions_ignore_already_matched(db: EntityDb, report: Mock):
    """If the name is non-unique but there is only one option available to match
    (i.e. if previous entities were matched by line number)
    do not report an ambiguous match."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 101, name="hello", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 500, name="hello", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 501, name="hello", type=EntityType.FUNCTION)
        # Match these addrs before calling match_functions()
        batch.match(100, 500)

    # 1 matched, 2 unmatched
    assert db.count() == 3

    match_functions(db, report)

    # Do not report
    report.assert_not_called()

    # Should combine the two unmatched entities
    assert assert_defined(db.get(ImageId.RECOMP, 501)).orig_addr == 101
    assert db.count() == 2


def test_match_function_names_truncate_255(db: EntityDb):
    """MSVC 4.2 truncates names to 255 characters in the PDB.
    Match function entities where the names are are equal up to the 255th character."""
    long_name = "x" * 255
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name=long_name + "y", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 555, name=long_name + "z", type=EntityType.FUNCTION)

    match_functions(db, truncate=True)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr == 555
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr == 123


def test_match_function_names_no_truncate(db: EntityDb):
    """Should recognize these as distinct names if truncate=False"""
    long_name = "x" * 255
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name=long_name + "y", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 555, name=long_name + "z", type=EntityType.FUNCTION)

    match_functions(db, truncate=False)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr is None
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr is None


#### match_vtables ####


def test_match_vtables(db: EntityDb):
    """Matching with the specific requirements on attributes for orig and recomp entities"""
    with db.batch() as batch:
        # Orig has class name and type
        batch.set(ImageId.ORIG, 100, name="Pizza", type=EntityType.VTABLE)
        # Recomp has full vtable name and type
        batch.set(ImageId.RECOMP, 200, name="Pizza::`vftable'", type=EntityType.VTABLE)

    match_vtables(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr == 200
    assert db.count() == 1


def test_match_vtables_no_match_recomp_name(db: EntityDb):
    """Recomp entity name must be in a specific format"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, name="Pizza", type=EntityType.VTABLE)
        batch.set(ImageId.RECOMP, 200, name="Pizza", type=EntityType.VTABLE)

    match_vtables(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr is None


def test_match_vtables_no_match_recomp_type(db: EntityDb):
    """Recomp entity must have type=EntityType.VTABLE"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, name="Pizza", type=EntityType.VTABLE)
        batch.set(ImageId.RECOMP, 200, name="Pizza::`vftable'")

    match_vtables(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr is None


def test_match_vtables_no_match_orig_type(db: EntityDb):
    """Orig entity must have type=EntityType.VTABLE"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, name="Pizza")
        batch.set(ImageId.RECOMP, 200, name="Pizza::`vftable'", type=EntityType.VTABLE)

    match_vtables(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr is None


def test_match_vtables_no_match_report(db: EntityDb, report: Mock):
    """Report a failure to match a vtable from the orig side."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, name="Pizza", type=EntityType.VTABLE)

    match_vtables(db, report)

    report.assert_called_with(ReccmpEvent.NO_MATCH, 100, msg=ANY)


def test_match_vtables_base_class(db: EntityDb):
    """Match a vtable with a base class"""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 100, name="Pizza", type=EntityType.VTABLE, base_class="Lunch"
        )
        batch.set(
            ImageId.RECOMP,
            200,
            name="Pizza::`vftable'{for `Lunch'}",
            type=EntityType.VTABLE,
        )

    match_vtables(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr == 200


def test_match_vtables_base_class_orig_none(db: EntityDb):
    """Do not match a multiple-inheritance vtable if the base class is not specified on the orig entity."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, name="Pizza", type=EntityType.VTABLE)
        batch.set(
            ImageId.RECOMP,
            200,
            name="Pizza::`vftable'{for `Lunch'}",
            type=EntityType.VTABLE,
        )

    match_vtables(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr is None


def test_match_vtables_base_class_same_as_derived(db: EntityDb):
    """Matching a vtable with the same base class and derived class.
    The base_class attribute is set on the orig entity."""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 100, name="Pizza", type=EntityType.VTABLE, base_class="Pizza"
        )
        batch.set(
            ImageId.RECOMP,
            200,
            name="Pizza::`vftable'{for `Pizza'}",
            type=EntityType.VTABLE,
        )

    match_vtables(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr == 200


def test_match_vtables_base_class_same_as_derived_orig_none(db: EntityDb):
    """If orig does not have the base_class attribute set, we can still match if
    the recomp vtable has the same base and derived class."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, name="Pizza", type=EntityType.VTABLE)
        batch.set(
            ImageId.RECOMP,
            200,
            name="Pizza::`vftable'{for `Pizza'}",
            type=EntityType.VTABLE,
        )

    match_vtables(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr == 200


def test_match_vtables_incompatible_base_class(db: EntityDb):
    """If the orig entity has a base_class, do not match with a recomp vtable that does not use multiple-inheritance."""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 100, name="Pizza", type=EntityType.VTABLE, base_class="Lunch"
        )
        batch.set(ImageId.RECOMP, 200, name="Pizza::`vftable'", type=EntityType.VTABLE)

    match_vtables(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr is None


def test_match_vtables_folded(db: EntityDb):
    """Match a folded vtable by trying each candidate name"""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            100,
            name="Pizza",
            type=EntityType.VTABLE,
            folded_vtables=[("Pizza", None), ("Lunch", None)],
        )
        batch.set(ImageId.RECOMP, 200, name="Lunch::`vftable'", type=EntityType.VTABLE)

    match_vtables(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr == 200


def test_match_vtables_folded_first_candidate(db: EntityDb):
    """The first folded candidate can match too, not just the last"""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            100,
            name="Pizza",
            type=EntityType.VTABLE,
            folded_vtables=[("Pizza", None), ("Lunch", None)],
        )
        batch.set(ImageId.RECOMP, 200, name="Pizza::`vftable'", type=EntityType.VTABLE)

    match_vtables(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr == 200


def test_match_vtables_folded_no_match(db: EntityDb, report: Mock):
    """Report a single failure if none of the folded candidates match."""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            100,
            name="Pizza",
            type=EntityType.VTABLE,
            folded_vtables=[("Pizza", None), ("Lunch", None)],
        )

    match_vtables(db, report)

    report.assert_called_once_with(ReccmpEvent.NO_MATCH, 100, msg=ANY)
    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr is None


#### match_static_variables ####


def test_match_static_var(db: EntityDb):
    """Match a static variable with all requirements satisfied."""
    with db.batch() as batch:
        # Orig entity function with symbol
        batch.set(
            ImageId.ORIG, 200, symbol="?Tick@IsleApp@@QAEXH@Z", type=EntityType.FUNCTION
        )
        # Static variable with symbol
        batch.set(
            ImageId.RECOMP, 500, symbol="?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA"
        )
        # Orig entity with variable name and link to orig function addr
        batch.set(
            ImageId.ORIG,
            600,
            name="g_startupDelay",
            parent_function=200,
            static_var=True,
            type=EntityType.DATA,
        )

    match_static_variables(db)

    assert assert_defined(db.get(ImageId.ORIG, 600)).recomp_addr == 500


def test_match_static_var_no_parent_function(db: EntityDb):
    """Cannot match static variable without a reference to its parent function"""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 200, symbol="?Tick@IsleApp@@QAEXH@Z", type=EntityType.FUNCTION
        )
        batch.set(
            ImageId.RECOMP, 500, symbol="?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA"
        )
        # No parent function
        batch.set(
            ImageId.ORIG,
            600,
            name="g_startupDelay",
            static_var=True,
            type=EntityType.DATA,
        )

    match_static_variables(db)

    assert assert_defined(db.get(ImageId.ORIG, 600)).recomp_addr is None


def test_match_static_var_static_false(db: EntityDb):
    """Cannot match static variable unless the static_var attribute is True"""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 200, symbol="?Tick@IsleApp@@QAEXH@Z", type=EntityType.FUNCTION
        )
        batch.set(
            ImageId.RECOMP, 500, symbol="?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA"
        )
        # static_var is not set
        batch.set(
            ImageId.ORIG,
            600,
            name="g_startupDelay",
            parent_function=200,
            type=EntityType.DATA,
        )

    match_static_variables(db)

    assert assert_defined(db.get(ImageId.ORIG, 600)).recomp_addr is None


def test_match_static_var_no_symbol_function(db: EntityDb):
    """Cannot match static variable if the parent function has no symbol"""
    with db.batch() as batch:
        # No symbol on parent function
        batch.set(ImageId.ORIG, 200, type=EntityType.FUNCTION)
        batch.set(
            ImageId.RECOMP, 500, symbol="?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA"
        )
        batch.set(
            ImageId.ORIG,
            600,
            name="g_startupDelay",
            parent_function=200,
            static_var=True,
            type=EntityType.DATA,
        )

    match_static_variables(db)

    assert assert_defined(db.get(ImageId.ORIG, 600)).recomp_addr is None


def test_match_static_var_no_symbol_variable(db: EntityDb):
    """Cannot match static variable without a symbol."""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 200, symbol="?Tick@IsleApp@@QAEXH@Z", type=EntityType.FUNCTION
        )
        # No symbol on variable
        batch.set(ImageId.RECOMP, 500, name="g_startupDelay")
        batch.set(
            ImageId.ORIG,
            600,
            name="g_startupDelay",
            parent_function=200,
            static_var=True,
            type=EntityType.DATA,
        )

    match_static_variables(db)

    assert assert_defined(db.get(ImageId.ORIG, 600)).recomp_addr is None


def test_match_static_var_no_match_report(db: EntityDb, report: Mock):
    """Report match failure for any orig entities with static_var=True"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 600, name="test", static_var=True, type=EntityType.DATA)

    match_static_variables(db, report)

    report.assert_called_with(ReccmpEvent.NO_MATCH, 600, msg=ANY)


#### match_variables ####


def test_match_variables(db: EntityDb, types: CvdumpTypesParser):
    """Simple match by name and type"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="hello", type=EntityType.DATA)
        batch.set(ImageId.RECOMP, 555, name="hello", type=EntityType.DATA)

    match_variables(db, types)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr == 555
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr == 123

    # Should combine entities
    assert db.count() == 1


def test_match_variables_no_match(db: EntityDb, types: CvdumpTypesParser):
    """Skip entities with no match"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="hello", type=EntityType.DATA)
        batch.set(ImageId.RECOMP, 555, name="test", type=EntityType.DATA)

    match_variables(db, types)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr is None
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr is None
    assert db.count() == 2


def test_match_variables_no_match_report(
    db: EntityDb, types: CvdumpTypesParser, report: Mock
):
    """Should report if we cannot match a name on the orig side."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="test", type=EntityType.DATA)

    match_variables(db, types, report)

    report.assert_called_with(ReccmpEvent.NO_MATCH, 123, msg=ANY)


def test_match_variables_type_null(db: EntityDb, types: CvdumpTypesParser):
    """Will allow a variable match if the recomp side has type=null"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="hello", type=EntityType.DATA)
        batch.set(ImageId.RECOMP, 555, name="hello")

    match_variables(db, types)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr == 555
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr == 123
    assert db.count() == 1


def test_match_variable_no_recomp_symbol_flag(
    db: EntityDb, types: CvdumpTypesParser, report: Mock
):
    """Does not report a warning if `no_recomp_symbol` is set on an orig symbol that does not match"""

    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 123, name="hello", type=EntityType.DATA, no_recomp_symbol=True
        )

    match_variables(db, types, report)

    report.assert_not_called()


TEST_CVDUMP_LINES = """
0x10e0 : Length = 86, Leaf = 0x1203 LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_REAL32(0040), offset = 0
        member name = 'x'
    list[1] = LF_MEMBER, public, type = T_REAL32(0040), offset = 4
        member name = 'y'
    list[2] = LF_MEMBER, public, type = T_REAL32(0040), offset = 8
        member name = 'z'

0x10e1 : Length = 34, Leaf = 0x1505 LF_STRUCTURE
    # members = 3,  field list type 0x10e0,
    Derivation list type 0x0000, VT shape type 0x0000
    Size = 12, class name = MyAnnotatedType, UDT(0x000010e1)
"""


def test_match_variable_annotation_lookup_success(
    db: EntityDb, types: CvdumpTypesParser, report: Mock
):
    """Successfully looks up a data type in the type database based on its annotation"""

    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            123,
            name="hello",
            type=EntityType.DATA,
            data_type_annotation="MyAnnotatedType",
            no_recomp_symbol=True,
        )

    types.read_all(TEST_CVDUMP_LINES)

    match_variables(db, types, report)

    report.assert_not_called()
    orig_entity = assert_defined(db.get(ImageId.ORIG, 123))
    assert orig_entity.get("data_type") == 0x10E1
    assert orig_entity.any_size() == 12


def test_match_variable_annotation_lookup_not_found(
    db: EntityDb, types: CvdumpTypesParser, report: Mock
):
    """Unsuccessfully looks up a data type in the type database based on its annotation"""

    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            123,
            name="hello",
            type=EntityType.DATA,
            data_type_annotation="MyAnnotatedType",
            no_recomp_symbol=True,
        )

    match_variables(db, types, report)

    report.assert_called_with(ReccmpEvent.INVALID_USER_DATA, 123, msg=ANY)


#### match_strings ####


def test_match_strings(db: EntityDb):
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="hello", type=EntityType.STRING)
        batch.set(ImageId.RECOMP, 555, name="hello", type=EntityType.STRING)

    match_strings(db)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr == 555
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr == 123

    # Should combine entities
    assert db.count() == 1


def test_match_strings_no_match(db: EntityDb):
    """Skip strings with no match"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="hello", type=EntityType.STRING)
        batch.set(ImageId.RECOMP, 555, name="test", type=EntityType.STRING)

    match_strings(db)

    assert assert_defined(db.get(ImageId.ORIG, 123)).recomp_addr is None
    assert assert_defined(db.get(ImageId.RECOMP, 555)).orig_addr is None
    assert db.count() == 2


def test_match_strings_type_required(db: EntityDb):
    """Do not match if one side is missing the type.
    This is a concern because we use the name attribute for the string's text."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, name="hello", type=EntityType.STRING)
        batch.set(ImageId.ORIG, 200, name="test")
        batch.set(ImageId.RECOMP, 500, name="hello")
        batch.set(ImageId.RECOMP, 600, name="test", type=EntityType.STRING)

    match_strings(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr is None
    assert assert_defined(db.get(ImageId.ORIG, 200)).recomp_addr is None


def test_match_strings_no_match_report(db: EntityDb, report: Mock):
    """Should report if we cannot match a string on the orig side.
    However: only alert if the string is 'verified' by user input,
    a symbol in the PDB, or some (future) heuristic."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="test", type=EntityType.STRING)

    match_strings(db, report)

    # Not verified: no alert for failed match
    report.assert_not_called()

    # Should alert after we mark the string as verified
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, verified=True)

    match_strings(db, report)
    report.assert_called_with(ReccmpEvent.NO_MATCH, 123, msg=ANY)


def test_match_strings_duplicates(db: EntityDb, report: Mock):
    """Binaries that do not de-dupe string should match duplicates by address order."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, name="hello", type=EntityType.STRING)
        batch.set(ImageId.ORIG, 200, name="hello", type=EntityType.STRING)
        batch.set(ImageId.ORIG, 300, name="hello", type=EntityType.STRING)
        batch.set(ImageId.RECOMP, 500, name="hello", type=EntityType.STRING)
        batch.set(ImageId.RECOMP, 600, name="hello", type=EntityType.STRING)
        batch.set(ImageId.RECOMP, 700, name="hello", type=EntityType.STRING)

    match_strings(db, report)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr == 500
    assert assert_defined(db.get(ImageId.ORIG, 200)).recomp_addr == 600
    assert assert_defined(db.get(ImageId.ORIG, 300)).recomp_addr == 700
    assert db.count() == 3

    # Do not alert for duplicate string matches.
    report.assert_not_called()


def test_match_strings_stable_order(db: EntityDb):
    """Duplicates are matched by address order, not db insertion order."""
    with db.batch() as batch:
        # Descending order
        batch.set(ImageId.ORIG, 300, name="hello", type=EntityType.STRING)
        batch.set(ImageId.ORIG, 200, name="hello", type=EntityType.STRING)
        batch.set(ImageId.ORIG, 100, name="hello", type=EntityType.STRING)
        batch.set(ImageId.RECOMP, 700, name="hello", type=EntityType.STRING)
        batch.set(ImageId.RECOMP, 600, name="hello", type=EntityType.STRING)
        batch.set(ImageId.RECOMP, 500, name="hello", type=EntityType.STRING)

    match_strings(db)

    assert assert_defined(db.get(ImageId.ORIG, 100)).recomp_addr == 500
    assert assert_defined(db.get(ImageId.ORIG, 200)).recomp_addr == 600
    assert assert_defined(db.get(ImageId.ORIG, 300)).recomp_addr == 700


def test_match_ref(db: EntityDb):
    """Match child entities that refer to the same matched parent entity, regardless of type."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100)
        batch.set(ImageId.RECOMP, 500)
        batch.match(100, 500)

        batch.set(ImageId.ORIG, 200)
        batch.set_ref(ImageId.ORIG, 200, ref=100)

        batch.set(ImageId.RECOMP, 600)
        batch.set_ref(ImageId.RECOMP, 600, ref=500)

    match_ref(db)

    assert assert_defined(db.get(ImageId.ORIG, 200)).recomp_addr == 600
    assert assert_defined(db.get(ImageId.RECOMP, 600)).orig_addr == 200


def test_match_ref_chained(db: EntityDb):
    """Match any child entities that refer to other child entities,
    provided we have a matched parent at the end of the chain."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100)
        batch.set(ImageId.RECOMP, 500)
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

    assert assert_defined(db.get(ImageId.ORIG, 200)).recomp_addr == 600
    assert assert_defined(db.get(ImageId.RECOMP, 600)).orig_addr == 200

    assert assert_defined(db.get(ImageId.ORIG, 300)).recomp_addr == 700
    assert assert_defined(db.get(ImageId.RECOMP, 700)).orig_addr == 300


def test_match_ref_parent_not_matched(db: EntityDb):
    """Don't match child entities if the parent is not matched."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100)
        batch.set(ImageId.RECOMP, 500)
        # Don't match parent entity.

        batch.set(ImageId.ORIG, 200)
        batch.set_ref(ImageId.ORIG, 200, ref=100)

        batch.set(ImageId.RECOMP, 600)
        batch.set_ref(ImageId.RECOMP, 600, ref=500)

    match_ref(db)

    # Child entities unchanged.
    assert assert_defined(db.get(ImageId.ORIG, 200)).recomp_addr is None
    assert assert_defined(db.get(ImageId.RECOMP, 600)).orig_addr is None


def test_match_ref_expected_order(db: EntityDb):
    """If there is more than one child entity that points to the same matched parent,
    match according to child address order."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100)
        batch.set(ImageId.RECOMP, 500)
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

    assert assert_defined(db.get(ImageId.ORIG, 200)).recomp_addr == 600
    assert assert_defined(db.get(ImageId.ORIG, 201)).recomp_addr == 601
    assert assert_defined(db.get(ImageId.ORIG, 202)).recomp_addr == 602


def test_match_ref_include_vtordisp(db: EntityDb):
    """If a displacement value is specified for the child entity (vtordisp)
    use it when matching the parent."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100)
        batch.set(ImageId.RECOMP, 500)
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
    assert assert_defined(db.get(ImageId.ORIG, 200)).recomp_addr == 600
    assert assert_defined(db.get(ImageId.ORIG, 201)).recomp_addr == 601


def test_match_ref_include_vtordisp_order(db: EntityDb):
    """For child entities with duplicate parent and displacement values, match
    by child address order.
    NOTE: It may not be possible for MSVC to duplicate vtordisps in this way."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100)
        batch.set(ImageId.RECOMP, 500)
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

    assert assert_defined(db.get(ImageId.ORIG, 200)).recomp_addr == 600
    assert assert_defined(db.get(ImageId.ORIG, 201)).recomp_addr == 601
    assert assert_defined(db.get(ImageId.ORIG, 202)).recomp_addr == 602


def test_match_ref_maximum_depth(db: EntityDb, report: Mock):
    """If we cannot match all referencing entities in 10 iterations, report a warning."""

    # No entities to match: should not report.
    match_ref(db, report)
    report.assert_not_called()

    # Run one iteration: should not report.
    with patch(
        "reccmp.compare.match_msvc.get_referencing_entity_matches",
        return_value=iter([(100, 100)]),
    ) as getter:
        match_ref(db, report)
        assert getter.call_count == 2  # Yields nothing on the second call.
        report.assert_not_called()

    # Run indefinitely: should report.
    with patch(
        "reccmp.compare.match_msvc.get_referencing_entity_matches",
        return_value=[(100, 100)],
    ) as getter:
        match_ref(db, report)
        assert getter.call_count == 10
        report.assert_called_once()


def test_match_imports(db: EntityDb):
    """Match import descriptors using case-insensitive pairing."""
    with db.batch() as batch:
        # Same case
        batch.set(ImageId.ORIG, 100, type=EntityType.IMPORT, name="TEST.DLL::Test")
        batch.set(ImageId.RECOMP, 100, type=EntityType.IMPORT, name="TEST.DLL::Test")

        # Different case
        batch.set(ImageId.ORIG, 200, type=EntityType.IMPORT, name="Test.Dll::Hello")
        batch.set(ImageId.RECOMP, 200, type=EntityType.IMPORT, name="TEST.DLL::hello")

    match_imports(db)

    e = db.get(ImageId.ORIG, 100)
    assert e is not None
    assert e.recomp_addr == 100

    e = db.get(ImageId.ORIG, 200)
    assert e is not None
    assert e.recomp_addr == 200
