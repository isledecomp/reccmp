from datetime import datetime
from dataclasses import dataclass
from typing import Literal
from pydantic import BaseModel
from reccmp.types import EntityType
from .diff import RawDiffOutput
from .internal import ReccmpReportEntity, ReccmpStatusReport


@dataclass
class JSONEntityVersion2:
    # pylint:disable=too-many-instance-attributes
    address: int
    name: str
    matching: float
    type: EntityType
    # Optional fields
    recomp: int | None = None
    stub: bool = False
    library: bool = False
    effective: bool = False
    rdiff: RawDiffOutput | None = None


class JSONReportVersion2(BaseModel):
    file: str
    format: Literal[2]
    timestamp: float
    data: list[JSONEntityVersion2]
    function_count: int | None = None


def _serialize_version_2(
    report: ReccmpStatusReport,
    diff_included: bool = False,
) -> JSONReportVersion2:
    entities = []

    for addr, e in report.entities.items():
        if not e.is_matched():
            continue

        # The dict key and the entity's `orig_addr` property should never differ.
        assert addr == e.orig_addr

        report_ent = JSONEntityVersion2(
            address=addr,
            name=e.name,
            matching=e.accuracy,
            recomp=e.recomp_addr,
            stub=e.is_stub,
            library=e.is_library,
            effective=e.is_effective_match,
            rdiff=e.rdiff if diff_included else None,
            type=e.type,
        )

        entities.append(report_ent)

    # Recalculate before freezing the value.
    report.update_function_count()

    return JSONReportVersion2(
        file=report.filename,
        format=2,
        timestamp=report.timestamp.timestamp(),
        data=entities,
        function_count=report.function_count,
    )


def _deserialize_version_2(obj: JSONReportVersion2) -> ReccmpStatusReport:
    report = ReccmpStatusReport(
        filename=obj.file,
        timestamp=datetime.fromtimestamp(obj.timestamp),
        from_version=2,
    )
    report.function_count = obj.function_count or 0

    for e in obj.data:
        report.entities[e.address] = ReccmpReportEntity(
            orig_addr=e.address,
            name=e.name,
            accuracy=e.matching,
            type=e.type,
            recomp_addr=e.recomp,
            is_stub=e.stub,
            is_library=e.library,
            is_effective_match=e.effective,
            rdiff=e.rdiff,
        )

    report.update_function_count()
    return report
