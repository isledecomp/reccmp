"""Reccmp reports: files that contain the comparison result from asmcmp."""

import pytest
from reccmp.compare.report import (
    ReccmpStatusReport,
    ReccmpComparedEntity,
    combine_reports,
    ReccmpReportSameSourceError,
)
from reccmp.types import EntityType


def create_report(
    entities: list[tuple[int, float]] | None = None,
) -> ReccmpStatusReport:
    """Helper to quickly set up a report to be customized further for each test."""
    report = ReccmpStatusReport(filename="test.exe")
    if entities is not None:
        for addr, accuracy in entities:
            report.entities[addr] = ReccmpComparedEntity(addr, "test", accuracy)

    return report


def test_aggregate_identity():
    """Combine a list of one report. Should get the same report back,
    except for expected differences like the timestamp."""
    report = create_report([(100, 1.0), (200, 0.5)])
    combined = combine_reports([report])

    for (a_key, a_entity), (b_key, b_entity) in zip(
        report.entities.items(), combined.entities.items()
    ):
        assert a_key == b_key
        assert a_entity.orig_addr == b_entity.orig_addr
        assert a_entity.accuracy == b_entity.accuracy


def test_aggregate_simple():
    """Should choose the best score from the sample reports."""
    x = create_report([(100, 0.8), (200, 0.2)])
    y = create_report([(100, 0.2), (200, 0.8)])

    combined = combine_reports([x, y])
    assert combined.entities[100].accuracy == 0.8
    assert combined.entities[200].accuracy == 0.8


def test_aggregate_union_all_addrs():
    """Should combine all addresses from any report."""
    x = create_report([(100, 0.8)])
    y = create_report([(200, 0.8)])

    combined = combine_reports([x, y])
    assert 100 in combined.entities
    assert 200 in combined.entities


def test_aggregate_stubs():
    """Stub functions (i.e. do not compare asm) are considered to have 0 percent accuracy."""
    x = create_report([(100, 0.9)])
    y = create_report([(100, 0.5)])

    # In a real report, accuracy would be zero for a stub.
    x.entities[100].is_stub = True
    y.entities[100].is_stub = False

    combined = combine_reports([x, y])
    assert combined.entities[100].is_stub is False

    # Choose the lower non-stub value
    assert combined.entities[100].accuracy == 0.5


def test_aggregate_all_stubs():
    """If all samples are stubs, preserve that setting."""
    x = create_report([(100, 1.0)])

    x.entities[100].is_stub = True

    combined = combine_reports([x, x])
    assert combined.entities[100].is_stub is True


def test_aggregate_100_over_effective():
    """Prefer 100% match over effective."""
    x = create_report([(100, 0.9)])
    y = create_report([(100, 1.0)])
    x.entities[100].is_effective_match = True

    combined = combine_reports([x, y])
    assert combined.entities[100].is_effective_match is False


def test_aggregate_effective_over_any():
    """Prefer effective match over any accuracy."""
    x = create_report([(100, 0.5)])
    y = create_report([(100, 0.6)])
    x.entities[100].is_effective_match = True
    # Y has higher accuracy score, but we could not confirm an effective match.

    combined = combine_reports([x, y])
    assert combined.entities[100].is_effective_match is True

    # Should retain original accuracy for effective match.
    assert combined.entities[100].accuracy == 0.5


def test_aggregate_different_files():
    """Should raise an exception if we try to aggregate reports
    where the orig filename does not match."""
    x = create_report()
    y = create_report()

    # Make sure they are different, regardless of what is set by create_report().
    x.filename = "test.exe"
    y.filename = "hello.exe"

    with pytest.raises(ReccmpReportSameSourceError):
        combine_reports([x, y])


def test_same_source():
    """Reports contain the filename of the original binary.
    If these filenames match case-insensitively, the reports
    came from the same reccmp target."""
    report_lower = ReccmpStatusReport(filename="test.exe")
    report_upper = ReccmpStatusReport(filename="TEST.EXE")
    report_mixed = ReccmpStatusReport(filename="Test.Exe")

    reports = (report_lower, report_upper, report_mixed)

    # Check all case-variant pairs, including identity
    for x, y in zip(reports, reports):
        assert x.has_same_source(y)

    # Check with different filename
    report_hello = ReccmpStatusReport(filename="hello.dll")
    for x in reports:
        assert x.has_same_source(report_hello) is False
        assert report_hello.has_same_source(x) is False


def test_aggregate_recomp_addr():
    """We combine the entity data based on the orig addr because this will not change.
    The recomp addr may vary a lot. If it is the same in all samples, use the value.
    Otherwise use a placeholder value."""
    x = create_report([(100, 0.8), (200, 0.2)])
    y = create_report([(100, 0.2), (200, 0.8)])
    # These recomp addrs match:
    x.entities[100].recomp_addr = 500
    y.entities[100].recomp_addr = 500
    # Y report has no addr for this
    x.entities[200].recomp_addr = 600

    combined = combine_reports([x, y])
    assert combined.entities[100].recomp_addr == 500
    assert combined.entities[200].recomp_addr != 600
    assert combined.entities[200].recomp_addr is None
    assert combined.entities[200].recomp_addr_varies


####  Entity filtering  ####


def add_entity(
    report: ReccmpStatusReport,
    addr: int,
    *,
    name: str = "test",
    accuracy: float = 1.0,
    entity_type: EntityType | None = EntityType.FUNCTION,
    library: bool = False,
) -> ReccmpComparedEntity:
    """Helper to add an entity with the attributes used by the filter tests."""
    entity = ReccmpComparedEntity(
        orig_addr=addr,
        name=name,
        accuracy=accuracy,
        type=entity_type,
        recomp_addr=addr,
        is_library=library,
    )
    report.entities[addr] = entity
    return entity


def test_filter_entity_behavior():
    """filter_entities() behaves the same as the main filter() function."""
    report = create_report([(100, 1.0), (200, 0.5)])

    report.filter_entities(lambda _: True)
    assert set(report.entities) == {100, 200}

    report.filter_entities(lambda _: False)
    assert not report.entities


def test_filter_entities_empty_report():
    """Filtering a report with no entities has no effect."""
    report = create_report()

    report.filter_entities(lambda _: False)
    assert not report.entities
    assert report.function_total == 0


def test_filter_entities_library():
    """Exclude library functions."""
    report = ReccmpStatusReport(filename="test.exe")
    add_entity(report, 100)
    add_entity(report, 200, library=True)
    add_entity(report, 300)

    report.filter_entities(lambda e: not e.is_library)
    assert set(report.entities) == {100, 300}


def test_filter_entities_function_name_exclude_list():
    """Exclude functions by name. Entities of any other type are unaffected,
    even if their name is in the exclusion list."""
    report = ReccmpStatusReport(filename="test.exe")
    add_entity(report, 100, name="Hello")
    add_entity(report, 200, name="Pizza")
    add_entity(report, 300, name="Pizza", entity_type=EntityType.VTABLE)

    exclude = {"Pizza"}
    report.filter_entities(
        lambda e: not (e.type == EntityType.FUNCTION and e.name in exclude)
    )
    assert set(report.entities) == {100, 300}


def test_filter_entities_untyped_is_not_function_type():
    """Potential gap: filtering on entity type instead of calling `entity.is_function()`
    will miss functions that have type=None (version 1 compatibility)."""
    report = ReccmpStatusReport(filename="test.exe")
    add_entity(report, 100, name="hello", entity_type=None)

    report.filter_entities(lambda e: e.type != EntityType.FUNCTION)
    assert set(report.entities) == {100}

    report.filter_entities(lambda e: not e.is_function())
    assert not report.entities


def test_filter_entities_sets_function_total():
    """Filtering resets the function count if it was never set."""
    report = ReccmpStatusReport(filename="test.exe")
    add_entity(report, 100)
    add_entity(report, 200)
    assert report.function_total == 0

    report.filter_entities(lambda _: True)
    assert report.function_total == 2


def test_filter_entities_reduces_function_total():
    """Discarded functions decrease the function count."""
    report = ReccmpStatusReport(filename="test.exe")
    add_entity(report, 100)
    add_entity(report, 200)
    add_entity(report, 300)

    report.filter_entities(lambda e: e.orig_addr != 200)
    assert report.function_total == 2


def test_filter_entities_function_total_ignores_other_types():
    """Only functions contribute to the function count,
    so discarding a vtable does not change it."""
    report = ReccmpStatusReport(filename="test.exe")
    add_entity(report, 100)
    add_entity(report, 200, entity_type=EntityType.VTABLE)

    report.filter_entities(lambda e: e.type != EntityType.VTABLE)
    assert set(report.entities) == {100}
    assert report.function_total == 1


def test_filter_entities_function_total_user_provided():
    """A user-provided function count is higher than the number of functions
    in the report. Discarding functions still reduces it by the amount removed."""
    report = ReccmpStatusReport(filename="test.exe")
    report.function_total = 100
    add_entity(report, 100)
    add_entity(report, 200)

    report.filter_entities(lambda e: e.orig_addr != 200)
    assert report.function_total == 99


def test_filter_entities_repeated():
    """Each call reduces the count against the entities that remain."""
    report = ReccmpStatusReport(filename="test.exe")
    add_entity(report, 100)
    add_entity(report, 200)
    add_entity(report, 300)

    report.filter_entities(lambda e: e.orig_addr != 100)
    assert report.function_total == 2

    report.filter_entities(lambda e: e.orig_addr != 200)
    assert set(report.entities) == {300}
    assert report.function_total == 1


def test_asmcmp_filtering_no_options():
    """Default options: retain everything."""
    report = ReccmpStatusReport(filename="test.exe")
    add_entity(report, 100, name="Hello")
    add_entity(report, 200, name="strcat", library=True)
    add_entity(report, 300, name="Hello::`vftable'", entity_type=EntityType.VTABLE)

    report.asmcmp_filtering(nolib=False, ignore_functions=[])
    assert set(report.entities) == {100, 200, 300}
    assert report.function_total == 2


def test_asmcmp_filtering_nolib():
    """--no-lib discards library entities of any type."""
    report = ReccmpStatusReport(filename="test.exe")
    add_entity(report, 100, name="Hello")
    add_entity(report, 200, name="strcat", library=True)
    add_entity(
        report,
        300,
        name="Hello::`vftable'",
        entity_type=EntityType.VTABLE,
        library=True,
    )

    report.asmcmp_filtering(nolib=True, ignore_functions=[])
    assert set(report.entities) == {100}

    # Only the discarded function reduces the count.
    assert report.function_total == 1


def test_asmcmp_filtering_ignore_functions():
    """Functions named in the ignore list are discarded.
    An entity of another type is retained even if its name is in the list."""
    report = ReccmpStatusReport(filename="test.exe")
    add_entity(report, 100, name="Hello")
    add_entity(report, 200, name="Pizza")
    add_entity(report, 300, name="Pizza::`vftable'", entity_type=EntityType.VTABLE)

    report.asmcmp_filtering(nolib=False, ignore_functions=["Pizza"])
    assert set(report.entities) == {100, 300}
    assert report.function_total == 1


def test_asmcmp_filtering_untyped_entity():
    """An entity with no type is treated as a function,
    so the ignore list applies to it. (Version 1 report compatibility.)"""
    report = ReccmpStatusReport(filename="test.exe")
    add_entity(report, 100, name="Pizza", entity_type=None)

    report.asmcmp_filtering(nolib=False, ignore_functions=["Pizza"])
    assert not report.entities
