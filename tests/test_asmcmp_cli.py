"""Command-line selection for reccmp-reccmp reports."""

from unittest.mock import patch

from reccmp.compare.diagnosis import (
    ComparisonAnalysis,
    ComparisonDifference,
    DifferenceSide,
)
from reccmp.tools.asmcmp import parse_args, triage_status_note


def test_parse_repeated_report_address_filters():
    argv = [
        "reccmp-reccmp",
        "--target",
        "TEST",
        "--orig-address",
        "0x401000",
        "--orig-address",
        "0x402000",
        "--recomp-address",
        "0x501000",
        "--no-cache",
    ]

    with patch("sys.argv", argv):
        args = parse_args()

    assert args.orig_address == [0x401000, 0x402000]
    assert args.recomp_address == [0x501000]
    assert args.no_cache


def test_triage_note_inconclusive_disclaims_source_defect():
    note = triage_status_note(ComparisonAnalysis.inconclusive("analysis_limit"))
    assert note is not None
    assert note.startswith("inconclusive:")
    assert "could not prove either outcome" in note
    assert "NOT evidence of a source defect" in note
    assert "verifier/metadata/alignment" in note


def test_triage_note_effective_says_no_action_needed():
    note = triage_status_note(ComparisonAnalysis.effective({"register_allocation"}))
    assert note == "effective: proved semantically harmless — no action needed"


def test_triage_note_exact_and_mismatch_have_no_gloss():
    assert triage_status_note(ComparisonAnalysis.exact()) is None

    difference = ComparisonDifference(
        "memory_address",
        DifferenceSide(0, 0x401000, {}),
        DifferenceSide(0, 0x501000, {}),
    )
    assert triage_status_note(ComparisonAnalysis.mismatch(difference)) is None
