from datetime import datetime
from dataclasses import dataclass
from typing import Literal, Iterable, Iterator
from pydantic import BaseModel, ValidationError
from pydantic_core import from_json
from reccmp.isledecomp.types import EntityType
from .diff import CombinedDiffOutput, RawDiffOutput, raw_diff_to_udiff


class ReccmpReportDeserializeError(Exception):
    """The given file is not a serialized reccmp report file"""


class ReccmpReportSameSourceError(Exception):
    """Tried to aggregate reports derived from different source files."""


@dataclass
class ReccmpComparedEntity:
    # pylint:disable=too-many-instance-attributes
    orig_addr: str
    name: str
    accuracy: float
    # Version 1 files have no type, so it is optional.
    type: EntityType | None = None
    recomp_addr: str | None = None
    is_effective_match: bool = False
    is_stub: bool = False
    rdiff: RawDiffOutput | None = None

    # Legacy field for importing version 1 files (aggregate).
    udiff: CombinedDiffOutput | None = None


class ReccmpStatusReport:
    # The filename of the original binary.
    # This is here to avoid comparing reports derived from different files.
    # TODO: in the future, we may want to use the hash instead
    filename: str

    # Creation date of the report file.
    timestamp: datetime

    # Using orig addr as the key.
    entities: dict[str, ReccmpComparedEntity]

    # Only set during deserialize.
    from_version: int | None

    def __init__(
        self,
        filename: str,
        timestamp: datetime | None = None,
        from_version: int | None = None,
    ) -> None:
        self.filename = filename
        self.from_version = from_version
        if timestamp is not None:
            self.timestamp = timestamp
        else:
            self.timestamp = datetime.now().replace(microsecond=0)

        self.entities = {}


def _get_entity_for_addr(
    samples: Iterable[ReccmpStatusReport], addr: str
) -> Iterator[ReccmpComparedEntity]:
    """Helper to return entities from xreports that have the given address."""
    for sample in samples:
        if addr in sample.entities:
            yield sample.entities[addr]


def _accuracy_sort_key(entity: ReccmpComparedEntity) -> float:
    """Helper to sort entity samples by accuracy score.
    100% match is preferred over effective match.
    Effective match is preferred over any accuracy.
    Stubs rank lower than any accuracy score."""
    if entity.is_stub:
        return -1.0

    if entity.accuracy == 1.0:
        if not entity.is_effective_match:
            return 1000.0

    if entity.is_effective_match:
        return 1.0

    return entity.accuracy


def combine_reports(samples: list[ReccmpStatusReport]) -> ReccmpStatusReport:
    """Combines the sample reports into a single report.
    The current strategy is to use the entity with the highest
    accuracy score from any report."""
    assert len(samples) > 0

    if not all(samples[0].filename == s.filename for s in samples):
        raise ReccmpReportSameSourceError

    output = ReccmpStatusReport(filename=samples[0].filename)

    # Combine every orig addr used in any of the reports.
    orig_addr_set = {key for sample in samples for key in sample.entities.keys()}

    all_orig_addrs = sorted(list(orig_addr_set))

    for addr in all_orig_addrs:
        e_list = list(_get_entity_for_addr(samples, addr))
        assert len(e_list) > 0

        # Our aggregate accuracy score is the highest from any report.
        e_list.sort(key=_accuracy_sort_key, reverse=True)

        output.entities[addr] = e_list[0]

        # Keep the recomp_addr if it is the same across all samples.
        # i.e. to detect where function alignment ends
        if not all(e_list[0].recomp_addr == e.recomp_addr for e in e_list):
            output.entities[addr].recomp_addr = "various"

    return output


#### JSON schemas and conversion functions ####


@dataclass
class JSONEntityVersion1:
    address: str
    name: str
    matching: float
    # Optional fields
    recomp: str | None = None
    stub: bool = False
    effective: bool = False
    diff: CombinedDiffOutput | None = None


class JSONReportVersion1(BaseModel):
    file: str
    format: Literal[1]
    timestamp: float
    data: list[JSONEntityVersion1]


def _create_udiff(entity: ReccmpComparedEntity) -> CombinedDiffOutput | None:
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


def _serialize_version_1(
    report: ReccmpStatusReport, diff_included: bool = False
) -> JSONReportVersion1:
    """The HTML file needs the diff data, but it is omitted from the JSON report."""
    entities = []

    for addr, e in report.entities.items():
        if diff_included:
            # An aggregate report may already have a deserialized udiff.
            udiff = e.udiff or _create_udiff(e)
        else:
            udiff = None

        entities.append(
            JSONEntityVersion1(
                address=addr,  # prefer dict key over redundant value in entity
                name=e.name,
                matching=e.accuracy,
                recomp=e.recomp_addr,
                stub=e.is_stub,
                effective=e.is_effective_match,
                diff=udiff,
            )
        )

    return JSONReportVersion1(
        file=report.filename,
        format=1,
        timestamp=report.timestamp.timestamp(),
        data=entities,
    )


def _deserialize_version_1(obj: JSONReportVersion1) -> ReccmpStatusReport:
    report = ReccmpStatusReport(
        filename=obj.file,
        timestamp=datetime.fromtimestamp(obj.timestamp),
        from_version=1,
    )

    for e in obj.data:
        report.entities[e.address] = ReccmpComparedEntity(
            orig_addr=e.address,
            name=e.name,
            accuracy=e.matching,
            recomp_addr=e.recomp,
            is_stub=e.stub,
            is_effective_match=e.effective,
            udiff=e.diff,
        )

    return report


def deserialize_reccmp_report(json_str: str) -> ReccmpStatusReport:
    try:
        obj = JSONReportVersion1.model_validate(from_json(json_str))
        return _deserialize_version_1(obj)
    except ValidationError as ex:
        raise ReccmpReportDeserializeError from ex


def serialize_reccmp_report(
    report: ReccmpStatusReport, diff_included: bool = False
) -> str:
    """Create a JSON string for the report so it can be written to a file."""
    now = datetime.now().replace(microsecond=0)
    report.timestamp = now
    obj = _serialize_version_1(report, diff_included=diff_included)

    return obj.model_dump_json(exclude_defaults=True)
