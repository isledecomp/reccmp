"""Reccmp reports: files that contain the comparison result from asmcmp."""
import pytest
from reccmp.isledecomp.compare.report import (
    ReccmpStatusReport,
    ReccmpComparedEntity,
    combine_reports,
    ReccmpReportSameSourceError,
)


def create_report(
    entities: list[tuple[str, float]] | None = None
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
    report = create_report([("100", 1.0), ("200", 0.5)])
    combined = combine_reports([report])

    for (a_key, a_entity), (b_key, b_entity) in zip(
        report.entities.items(), combined.entities.items()
    ):
        assert a_key == b_key
        assert a_entity.orig_addr == b_entity.orig_addr
        assert a_entity.accuracy == b_entity.accuracy


def test_aggregate_simple():
    """Should choose the best score from the sample reports."""
    x = create_report([("100", 0.8), ("200", 0.2)])
    y = create_report([("100", 0.2), ("200", 0.8)])

    combined = combine_reports([x, y])
    assert combined.entities["100"].accuracy == 0.8
    assert combined.entities["200"].accuracy == 0.8


def test_aggregate_union_all_addrs():
    """Should combine all addresses from any report."""
    x = create_report([("100", 0.8)])
    y = create_report([("200", 0.8)])

    combined = combine_reports([x, y])
    assert "100" in combined.entities
    assert "200" in combined.entities


def test_aggregate_stubs():
    """Stub functions (i.e. do not compare asm) are considered to have 0 percent accuracy."""
    x = create_report([("100", 0.9)])
    y = create_report([("100", 0.5)])

    # In a real report, accuracy would be zero for a stub.
    x.entities["100"].is_stub = True
    y.entities["100"].is_stub = False

    combined = combine_reports([x, y])
    assert combined.entities["100"].is_stub is False

    # Choose the lower non-stub value
    assert combined.entities["100"].accuracy == 0.5


def test_aggregate_all_stubs():
    """If all samples are stubs, preserve that setting."""
    x = create_report([("100", 1.0)])

    x.entities["100"].is_stub = True

    combined = combine_reports([x, x])
    assert combined.entities["100"].is_stub is True


def test_aggregate_100_over_effective():
    """Prefer 100% match over effective."""
    x = create_report([("100", 0.9)])
    y = create_report([("100", 1.0)])
    x.entities["100"].is_effective_match = True

    combined = combine_reports([x, y])
    assert combined.entities["100"].is_effective_match is False


def test_aggregate_effective_over_any():
    """Prefer effective match over any accuracy."""
    x = create_report([("100", 0.5)])
    y = create_report([("100", 0.6)])
    x.entities["100"].is_effective_match = True
    # Y has higher accuracy score, but we could not confirm an effective match.

    combined = combine_reports([x, y])
    assert combined.entities["100"].is_effective_match is True

    # Should retain original accuracy for effective match.
    assert combined.entities["100"].accuracy == 0.5


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


def test_aggregate_recomp_addr():
    """We combine the entity data based on the orig addr because this will not change.
    The recomp addr may vary a lot. If it is the same in all samples, use the value.
    Otherwise use a placeholder value."""
    x = create_report([("100", 0.8), ("200", 0.2)])
    y = create_report([("100", 0.2), ("200", 0.8)])
    # These recomp addrs match:
    x.entities["100"].recomp_addr = "500"
    y.entities["100"].recomp_addr = "500"
    # Y report has no addr for this
    x.entities["200"].recomp_addr = "600"

    combined = combine_reports([x, y])
    assert combined.entities["100"].recomp_addr == "500"
    assert combined.entities["200"].recomp_addr != "600"
    # TODO: string subject to change? better to leave as none?
    assert combined.entities["200"].recomp_addr == "various"
