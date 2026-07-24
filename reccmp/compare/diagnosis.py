"""Stable structured results for semantic comparison diagnosis.

This module intentionally contains only the small, generic vocabulary shared by
the verifier, JSON reports, and downstream tools.  Symbolic execution and report
formatting remain in their existing layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TypeAlias

FactValue: TypeAlias = str | int | bool | None


class ComparisonStatus(Enum):
    EXACT = "exact"
    EFFECTIVE = "effective"
    MISMATCH = "mismatch"
    INCONCLUSIVE = "inconclusive"


EFFECTIVE_REASON_ORDER = (
    "register_allocation",
    "frame_slot_layout",
    "callee_save_substitution",
    "instruction_reorder",
    "commutative_order",
    "condition_inversion",
    "load_folding",
    "dead_operation",
    "padding",
    # The original function is a stale incremental-link jmp island whose fold
    # chain lands on a proven-equivalent shared body (configured via the
    # project's equivalence-groups metadata); the recomp emits the real body.
    "folded_symbol_alias",
)

EFFECTIVE_REASONS = frozenset(EFFECTIVE_REASON_ORDER)

MISMATCH_KINDS = frozenset(
    {
        "call_target",
        "call_argument",
        "memory_address",
        "memory_value",
        "immediate_value",
        "branch_condition",
        "branch_target",
        "return_value",
        "preserved_state",
        "symbol_resolution",
    }
)

INCONCLUSIVE_REASONS = frozenset(
    {
        "unsupported_instruction",
        "unsupported_control_flow",
        "alignment_failure",
        "missing_metadata",
        "analysis_limit",
    }
)


def normalize_effective_reasons(reasons) -> tuple[str, ...]:
    """Validate, deduplicate, and order the fixed reason vocabulary."""
    values = set(reasons)
    unknown = values - EFFECTIVE_REASONS
    if unknown:
        raise ValueError(f"Unknown effective reasons: {sorted(unknown)}")
    return tuple(reason for reason in EFFECTIVE_REASON_ORDER if reason in values)


@dataclass(frozen=True)
class DifferenceSide:
    instruction_index: int | None = None
    address: int | None = None
    facts: dict[str, FactValue] = field(default_factory=dict)


@dataclass(frozen=True)
class ComparisonDifference:
    kind: str
    orig: DifferenceSide
    recomp: DifferenceSide

    def __post_init__(self) -> None:
        if self.kind not in MISMATCH_KINDS:
            raise ValueError(f"Unknown mismatch kind: {self.kind}")


@dataclass(frozen=True)
class ComparisonAnalysis:
    status: ComparisonStatus
    effective_reasons: tuple[str, ...] = ()
    difference: ComparisonDifference | None = None
    inconclusive_reason: str | None = None
    inconclusive_location: DifferenceSide | None = None

    def __post_init__(self) -> None:
        normalized = normalize_effective_reasons(self.effective_reasons)
        object.__setattr__(self, "effective_reasons", normalized)
        if self.status != ComparisonStatus.EFFECTIVE and normalized:
            raise ValueError("Only effective results carry proof reasons")
        if self.status == ComparisonStatus.MISMATCH and self.difference is None:
            raise ValueError("A mismatch must include a concrete difference")
        if self.status != ComparisonStatus.MISMATCH and self.difference is not None:
            raise ValueError("Only mismatch results carry a difference")
        if self.status == ComparisonStatus.INCONCLUSIVE:
            if self.inconclusive_reason not in INCONCLUSIVE_REASONS:
                raise ValueError(
                    f"Unknown inconclusive reason: {self.inconclusive_reason}"
                )
        elif self.inconclusive_reason is not None:
            raise ValueError("Only inconclusive results carry an inconclusive reason")
        if (
            self.status != ComparisonStatus.INCONCLUSIVE
            and self.inconclusive_location is not None
        ):
            raise ValueError("Only inconclusive results carry an analysis location")

    @property
    def is_effective(self) -> bool:
        return self.status in (ComparisonStatus.EXACT, ComparisonStatus.EFFECTIVE)

    @classmethod
    def exact(cls) -> "ComparisonAnalysis":
        return cls(ComparisonStatus.EXACT)

    @classmethod
    def effective(cls, reasons) -> "ComparisonAnalysis":
        return cls(ComparisonStatus.EFFECTIVE, tuple(reasons))

    @classmethod
    def mismatch(cls, difference: ComparisonDifference) -> "ComparisonAnalysis":
        return cls(ComparisonStatus.MISMATCH, difference=difference)

    @classmethod
    def inconclusive(
        cls, reason: str, location: DifferenceSide | None = None
    ) -> "ComparisonAnalysis":
        return cls(
            ComparisonStatus.INCONCLUSIVE,
            inconclusive_reason=reason,
            inconclusive_location=location,
        )


@dataclass
class AnalysisRecorder:
    """Mutable evidence sink used by one speculative verifier strategy."""

    orig_addrs: list[int | None] | None = None
    recomp_addrs: list[int | None] | None = None
    reasons: set[str] = field(default_factory=set)
    difference: ComparisonDifference | None = None
    candidate_difference: ComparisonDifference | None = None
    inconclusive_reason: str | None = None
    inconclusive_location: DifferenceSide | None = None

    def side(
        self, which: str, instruction_index: int | None, facts: dict[str, FactValue]
    ) -> DifferenceSide:
        addrs = self.orig_addrs if which == "orig" else self.recomp_addrs
        address = None
        if addrs is not None and instruction_index is not None:
            if 0 <= instruction_index < len(addrs):
                address = addrs[instruction_index]
        return DifferenceSide(instruction_index, address, facts)

    def record_difference(
        self,
        kind: str,
        orig_index: int | None,
        recomp_index: int | None,
        orig_facts: dict[str, FactValue],
        recomp_facts: dict[str, FactValue],
        *,
        candidate: bool = False,
    ) -> None:
        difference = ComparisonDifference(
            kind,
            self.side("orig", orig_index, orig_facts),
            self.side("recomp", recomp_index, recomp_facts),
        )
        if candidate:
            if self.candidate_difference is None:
                self.candidate_difference = difference
        elif self.difference is None:
            self.difference = difference

    def mark_inconclusive(
        self,
        reason: str,
        orig_index: int | None = None,
        recomp_index: int | None = None,
    ) -> None:
        if reason not in INCONCLUSIVE_REASONS:
            raise ValueError(f"Unknown inconclusive reason: {reason}")
        if self.inconclusive_reason is None:
            self.inconclusive_reason = reason
            if orig_index is not None:
                self.inconclusive_location = self.side("orig", orig_index, {})
            elif recomp_index is not None:
                self.inconclusive_location = self.side("recomp", recomp_index, {})

    @property
    def best_difference(self) -> ComparisonDifference | None:
        if self.difference is None:
            return self.candidate_difference
        if self.candidate_difference is None:
            return self.difference
        if self.difference.kind in {
            "call_target",
            "call_argument",
            "branch_condition",
            "branch_target",
        }:
            return self.difference
        if (
            self.difference.kind == "return_value"
            and self.candidate_difference.kind == "immediate_value"
        ):
            return self.difference
        concrete_index = self.difference.orig.instruction_index
        candidate_index = self.candidate_difference.orig.instruction_index
        if candidate_index is not None and (
            concrete_index is None or candidate_index < concrete_index
        ):
            return self.candidate_difference
        return self.difference

    def effective_analysis(self, extra_reasons=()) -> ComparisonAnalysis:
        return ComparisonAnalysis.effective(self.reasons | set(extra_reasons))

    def failure_analysis(self) -> ComparisonAnalysis:
        if self.best_difference is not None:
            return ComparisonAnalysis.mismatch(self.best_difference)
        return ComparisonAnalysis.inconclusive(
            self.inconclusive_reason or "analysis_limit", self.inconclusive_location
        )
