from datetime import datetime
from dataclasses import dataclass
from typing import Literal
from pydantic import BaseModel
from reccmp.types import EntityType
from .diff import CombinedDiffOutput, raw_diff_to_udiff
from .internal import ReccmpReportEntity, ReccmpStatusReport, format_address


def get_udiff_for_entity(entity: ReccmpReportEntity) -> CombinedDiffOutput | None:
    """Create a unified diff for this entity to add to a version 1 report.

    If the entity was imported from a version 1 report and we already have a unified diff, use it.
    This can occur with `reccmp-aggregate` where we copy the entity with the highest accuracy score.

    If there is no unified diff, create a new one using the entity's raw diff, if it exists.

    If we return None, no diff is possible because the entity matches 100%, is a stub,
    or was created from a deserialized report without diff data."""
    if entity.udiff is not None:
        # An aggregate report may already have a deserialized udiff.
        return entity.udiff

    if entity.rdiff is None:
        # We need data to create the unified diff.
        return None

    if entity.type == EntityType.VTABLE:
        # Complete diff is always shown for vtables, even if they match.
        return raw_diff_to_udiff(entity.rdiff, grouped=False)

    if entity.is_effective_match or entity.accuracy != 1.0:
        # Show grouped diff for effective match.
        return raw_diff_to_udiff(entity.rdiff, grouped=True)

    # Display nothing for matching functions.
    return None


@dataclass
class JSONEntityVersion1:
    # pylint:disable=too-many-instance-attributes
    address: str
    name: str
    matching: float
    # Optional fields
    recomp: str | None = None
    stub: bool | None = False
    library: bool | None = False
    effective: bool | None = False
    diff: CombinedDiffOutput | None = None
    # EntityType as int. Older reports do not include this field.
    type: int | None = None


class JSONReportVersion1(BaseModel):
    file: str
    format: Literal[1]
    timestamp: float
    data: list[JSONEntityVersion1]

    # Did not exist before July 2026.
    function_count: int | None = None


MAGIC_STRING_VARIOUS = "various"
"""reccmp-aggregate uses this to indicate an entity whose recomp addr varied between the sample reports."""


def _deserialize_version_1_type(entity_type: int | None, name: str) -> EntityType:
    try:
        # Try to use the given type.
        output = EntityType(entity_type or EntityType.FUNCTION)
    except ValueError:
        output = EntityType.FUNCTION

    if output != EntityType.FUNCTION:
        return output

    if "`vftable" in name:
        return EntityType.VTABLE

    if "`vtordisp" in name:
        return EntityType.VTORDISP

    return output


def _serialize_version_1(
    report: ReccmpStatusReport,
    diff_included: bool = False,
) -> JSONReportVersion1:
    """The JSON report can exclude the diff to make deserialization faster."""
    entities = []

    for addr, e in report.entities.items():
        if not e.is_matched():
            continue

        # The dict key and the entity's `orig_addr` property should never differ.
        assert addr == e.orig_addr

        report_ent = JSONEntityVersion1(
            address=format_address(addr),
            name=e.name,
            matching=e.accuracy,
            recomp=(
                format_address(e.recomp_addr)
                if e.recomp_addr is not None
                else (MAGIC_STRING_VARIOUS if e.recomp_addr_varies else "")
            ),
            stub=e.is_stub,
            library=e.is_library,
            effective=e.is_effective_match,
            diff=get_udiff_for_entity(e) if diff_included else None,
            type=int(e.type),
        )

        entities.append(report_ent)

    # Recalculate before freezing the value.
    report.update_function_count()

    return JSONReportVersion1(
        file=report.filename,
        format=1,
        timestamp=report.timestamp.timestamp(),
        data=entities,
        function_count=report.function_count,
    )


def _deserialize_version_1(obj: JSONReportVersion1) -> ReccmpStatusReport:
    report = ReccmpStatusReport(
        filename=obj.file,
        timestamp=datetime.fromtimestamp(obj.timestamp),
        from_version=1,
    )
    report.function_count = obj.function_count or 0

    for e in obj.data:
        orig_addr = int(e.address, 16)

        if e.recomp == MAGIC_STRING_VARIOUS:
            recomp_addr = None
            various = True
        else:
            recomp_addr = int(e.recomp, 16) if e.recomp is not None else None
            various = False

        report.entities[orig_addr] = ReccmpReportEntity(
            orig_addr=orig_addr,
            name=e.name,
            accuracy=e.matching,
            type=_deserialize_version_1_type(e.type, e.name),
            recomp_addr=recomp_addr,
            is_stub=bool(e.stub),
            is_library=bool(e.library),
            is_effective_match=bool(e.effective),
            udiff=e.diff,
            recomp_addr_varies=various,
        )

    report.update_function_count()
    return report
