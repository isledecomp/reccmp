"""Command-line selection for reccmp-reccmp reports."""

from unittest.mock import patch

from reccmp.compare.diagnosis import (
    ComparisonAnalysis,
    ComparisonDifference,
    DifferenceSide,
)
from reccmp.compare.report import ReccmpComparedEntity
from reccmp.tools.asmcmp import (
    inconclusive_diagnostic_text,
    parse_args,
    semantic_similarity_text,
    triage_status_note,
)


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


def test_semantic_similarity_text_keeps_raw_score_visible():
    difference = ComparisonDifference(
        "memory_value",
        DifferenceSide(1, 0x401002, {}),
        DifferenceSide(1, 0x501002, {}),
    )
    match = ReccmpComparedEntity(
        0x401000,
        "Example",
        0.25,
        analysis=ComparisonAnalysis.mismatch(
            difference,
            semantic_similarity=0.75,
        ),
    )
    text = semantic_similarity_text(match)
    assert text is not None
    assert "75.00%" in text
    assert "semantic similarity (diagnostic" in text
    assert "25.00%" in text
    assert "raw" in text


def test_inconclusive_diagnostic_renders_reason_location_and_facts():
    analysis = ComparisonAnalysis.inconclusive(
        "non_isomorphic_cfg",
        DifferenceSide(
            4,
            0x401020,
            {
                "failure": "edge_roles",
                "orig_block_count": 8,
                "recomp_block_count": 9,
            },
        ),
    )
    text = inconclusive_diagnostic_text(analysis)
    assert text is not None
    assert "non isomorphic cfg" in text
    assert "0x401020" in text
    assert "failure: edge_roles" in text
    assert "orig block count: 8" in text
    assert "recomp block count: 9" in text
