"""Diagnostics for entity metadata that limits or blocks comparison."""

from dataclasses import dataclass
import logging
import struct

from reccmp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.formats.image import Image
from reccmp.types import EntityType, ImageId

from .db import EntityDb, ReccmpMatch

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _VtableSizeEvidence:  # pylint: disable=too-many-instance-attributes
    candidate_size: int
    orig_size: int | None
    orig_max: int | None
    recomp_size: int | None
    recomp_max: int | None
    orig_bound_slots: int | None
    first_null_slot: int | None
    null_scan_complete: bool
    triggers: tuple[str, ...]
    boundary: str | None

    @property
    def candidate_slots(self) -> int:
        return self.candidate_size // 4


def _first_null_slot(
    orig_bin: Image, address: int, size: int
) -> tuple[int | None, bool]:
    """Return the first null pointer slot and whether the full scan succeeded."""
    scan_size = 4 * (size // 4)
    if scan_size == 0:
        return None, True
    try:
        table = orig_bin.read(address, scan_size)
    except (InvalidVirtualAddressError, InvalidVirtualReadError):
        return None, False
    for slot, (target,) in enumerate(struct.iter_unpack("<L", table)):
        if target == 0:
            return slot, True
    return None, True


def _boundary_description(
    db: EntityDb, match: ReccmpMatch, orig_max: int | None
) -> str | None:
    if orig_max is None:
        return None
    address = match.orig_addr + orig_max
    entity = db.get(ImageId.ORIG, address)
    if entity is None:
        return f"0x{address:08x} (unknown entity)"

    parts = [f"0x{address:08x}"]
    if name := entity.best_name():
        parts.append(name)
    if entity.entity_type is not None:
        try:
            parts.append(f"({EntityType(entity.entity_type).name.lower()})")
        except ValueError:
            parts.append(f"(type {entity.entity_type})")
    return " ".join(parts)


def _collect_vtable_size_evidence(
    db: EntityDb, match: ReccmpMatch, orig_bin: Image
) -> _VtableSizeEvidence:
    candidate_size = match.any_size()
    orig_size = match.size(ImageId.ORIG)
    orig_max = match.max_size(ImageId.ORIG)
    recomp_size = match.size(ImageId.RECOMP)
    recomp_max = match.max_size(ImageId.RECOMP)

    bounds = [value for value in (orig_size, orig_max) if value is not None]
    orig_bound = min(bounds) if bounds else None
    first_null_slot, null_scan_complete = _first_null_slot(
        orig_bin, match.orig_addr, candidate_size
    )

    triggers = []
    if orig_size is not None and orig_size < candidate_size:
        triggers.append("declared_size")
    if orig_max is not None and orig_max < candidate_size:
        triggers.append("boundary")
    if first_null_slot is not None and first_null_slot < candidate_size // 4:
        triggers.append("null")

    return _VtableSizeEvidence(
        candidate_size=candidate_size,
        orig_size=orig_size,
        orig_max=orig_max,
        recomp_size=recomp_size,
        recomp_max=recomp_max,
        orig_bound_slots=orig_bound // 4 if orig_bound is not None else None,
        first_null_slot=first_null_slot,
        null_scan_complete=null_scan_complete,
        triggers=tuple(triggers),
        boundary=(
            _boundary_description(db, match, orig_max)
            if "boundary" in triggers
            else None
        ),
    )


def _format_vtable_size_warning(
    match: ReccmpMatch, evidence: _VtableSizeEvidence
) -> str:
    first_null = (
        str(evidence.first_null_slot)
        if evidence.null_scan_complete and evidence.first_null_slot is not None
        else "None" if evidence.null_scan_complete else "unavailable"
    )
    lines = [
        f"Recomp vtable is larger than orig vtable for {match.name}",
        (
            f"  addresses orig=0x{match.orig_addr:08x} "
            f"recomp=0x{match.recomp_addr:08x}"
        ),
        (
            f"  slots candidate={evidence.candidate_slots} "
            f"orig_bound={evidence.orig_bound_slots} "
            f"first_null={first_null} trigger={','.join(evidence.triggers)}"
        ),
        (
            f"  bytes orig_size={evidence.orig_size} orig_max={evidence.orig_max} "
            f"recomp_size={evidence.recomp_size} "
            f"recomp_max={evidence.recomp_max} any={evidence.candidate_size}"
        ),
    ]
    if evidence.boundary is not None:
        lines.append(f"  boundary {evidence.boundary}")
    return "\n".join(lines)


def check_vtables(
    db: EntityDb, orig_bin: Image, name_filter: str | None = None
) -> None:
    """Report why a recompiled vtable appears larger than the original.

    The original extent may be bounded by explicit size metadata, the next
    solid entity, or a null pointer in the original bytes.  Report all evidence
    rather than only the first trigger: an interior stale entity and a genuine
    adjacent table both look like a short max-size boundary until their names
    and the original non-null span are visible.
    """
    for match in db.get_matches_by_type(EntityType.VTABLE):
        if name_filter is not None and name_filter not in (match.name or "").lower():
            continue
        assert (
            match.name is not None
            and match.orig_addr is not None
            and match.recomp_addr is not None
        )
        evidence = _collect_vtable_size_evidence(db, match, orig_bin)
        if evidence.triggers:
            logger.warning(_format_vtable_size_warning(match, evidence))
