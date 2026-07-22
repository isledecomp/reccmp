from datetime import datetime
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Literal, cast

from pydantic import BaseModel, ValidationError
from pydantic_core import from_json

from reccmp.types import EntityType

from .diagnosis import (
    ComparisonAnalysis,
    ComparisonDifference,
    ComparisonStatus,
    DifferenceSide,
)
from .diff import (
    CombinedDiffOutput,
    MatchingOrMismatchingBlock,
    RawDiffOutput,
    raw_diff_to_udiff,
)


def format_address(addr: int) -> str:
    """This is here just to document each spot where we
    convert an int address into a string.
    In the future, the format may be customizable. (GH #370)"""
    return f"{addr:#x}"


class ReccmpReportDeserializeError(Exception):
    """The given file is not a serialized reccmp report file"""


class ReccmpReportSameSourceError(Exception):
    """Tried to aggregate reports derived from different source files."""


@dataclass
class ReccmpComparedEntity:
    # pylint:disable=too-many-instance-attributes
    orig_addr: int
    name: str
    accuracy: float
    type: EntityType | None = None
    recomp_addr: int | None = None
    """The meaning of `None` depends on `recomp_addr_varies`:
    recomp_addr_varies is False: This entity is unmatched.
    recomp_addr_varies is True:  This entity has no fixed recomp addr."""

    analysis: ComparisonAnalysis = ComparisonAnalysis.inconclusive("analysis_limit")
    is_stub: bool = False
    is_library: bool = False
    rdiff: RawDiffOutput | None = None
    report_diff: CombinedDiffOutput | None = None

    # Legacy field for importing version 1 files (aggregate).
    udiff: CombinedDiffOutput | None = None

    recomp_addr_varies: bool = False
    """True if this entity had no fixed recomp address across the
    samples combined by reccmp-aggregate."""

    def is_matched(self) -> bool:
        return self.recomp_addr is not None or self.recomp_addr_varies

    def is_function(self) -> bool:
        """Entities without a type (derived from older reports that did not
        serialize this field) are considered functions to maintain compatibility."""
        return self.type is None or self.type == EntityType.FUNCTION

    @property
    def is_effective_match(self) -> bool:
        return self.analysis.status == ComparisonStatus.EFFECTIVE

    @property
    def effective_accuracy(self) -> float:
        return 1.0 if self.is_effective_match else self.accuracy


class ReccmpStatusReport:
    filename: str
    """The filename of the original binary.
    This is here to avoid comparing reports derived from different files.
    TODO: in the future, we may want to use the hash instead"""

    timestamp: datetime
    """Creation date of the report file."""

    entities: dict[int, ReccmpComparedEntity]
    """Using orig addr as the key."""

    from_version: int | None
    """Only set during deserialize. (Not used yet)"""

    function_count: int = 0
    """Function count used to determine progress percentage and other statistics.
    We can compute this value from the report's entities or use a user-provided value.
    We will use whichever is higher so progress cannot exceed 100%."""

    def __init__(
        self,
        filename: str,
        timestamp: datetime | None = None,
        from_version: int | None = None,
    ) -> None:
        self.filename = filename
        self.from_version = from_version
        self.function_count = 0
        if timestamp is not None:
            self.timestamp = timestamp
        else:
            self.timestamp = datetime.now().replace(microsecond=0)

        self.entities = {}

    def add_match(self, match: ReccmpComparedEntity):
        self.entities[match.orig_addr] = match

    def has_same_source(self, other: "ReccmpStatusReport") -> bool:
        """Were both reports derived from the same reccmp target?"""
        return self.filename.lower() == other.filename.lower()

    def update_function_count(self) -> None:
        counted_type = sum(1 for ent in self.entities.values() if ent.is_function())
        self.function_count = max(self.function_count, counted_type)

    def filter_entities(
        self, filter_fn: Callable[[ReccmpComparedEntity], bool]
    ) -> None:
        """Delete entities that return False from the provided filter function."""
        # Set the count in case it has never been set.
        self.update_function_count()

        discarded = [
            key for key, value in self.entities.items() if not filter_fn(value)
        ]

        # Only functions contribute to function_count.
        functions_removed = sum(
            1 for key in discarded if self.entities[key].is_function()
        )

        for key in discarded:
            del self.entities[key]

        # Manually decrease it because recalculating will use
        # the higher of either the previous or current count.
        self.function_count -= functions_removed

    def asmcmp_filtering(self, nolib: bool, ignore_functions: list[str]) -> None:
        """Helper to filter the report using the current filter options from `reccmp-reccmp`.
        Compare with `entity_filter` in asmcmp.py that acts on the `ReccmpEntity` object.
        """

        def entity_filter(entity: ReccmpComparedEntity) -> bool:
            if entity.is_function() and entity.name in ignore_functions:
                return False

            if nolib and entity.is_library:
                return False

            return True

        self.filter_entities(entity_filter)


def report_function_alignment(report: ReccmpStatusReport) -> int:
    """Report the count of all (non-contiguous) functions where
    the address is the same in both binaries."""
    count = 0
    for ent in report.entities.values():
        if ent.is_function() and ent.orig_addr == ent.recomp_addr:
            count += 1

    return count


def report_function_accuracy(report: ReccmpStatusReport) -> tuple[int, float, float]:
    """Collects the accuracy and effective accuracy of all compared functions in the report.
    Returns (implemented_count, total_accuracy, total_effective_accuracy).
    Stubs are not compared so they are excluded.
    The accuracy scores are raw score values. Divide by the implemented_count to get the percentage.
    """
    implemented_count = 0
    total_accuracy = 0.0
    total_effective_accuracy = 0.0

    for ent in report.entities.values():
        if ent.is_function() and ent.is_matched() and not ent.is_stub:
            implemented_count += 1
            total_accuracy += ent.accuracy
            total_effective_accuracy += ent.effective_accuracy

    return (implemented_count, total_accuracy, total_effective_accuracy)


def _get_entity_for_addr(
    samples: Iterable[ReccmpStatusReport], addr: int
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

    if not all(samples[0].has_same_source(s) for s in samples):
        raise ReccmpReportSameSourceError

    output = ReccmpStatusReport(filename=samples[0].filename)

    # Use the highest function total across all samples.
    # Some functions may have been inlined in some reports.
    output.function_count = max(sample.function_count for sample in samples)

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
            output.entities[addr].recomp_addr = None
            output.entities[addr].recomp_addr_varies = True

    # Recalculate the count against the functions we actually have.
    # This may be higher than the count from any one sample.
    output.update_function_count()

    return output


def get_udiff_for_entity(entity: ReccmpComparedEntity) -> CombinedDiffOutput | None:
    """Create a unified diff for this entity to add to a version 1 report.

    If the entity was imported from a version 1 report and we already have a unified diff, use it.
    This can occur with `reccmp-aggregate` where we copy the entity with the highest accuracy score.

    If there is no unified diff, create a new one using the entity's raw diff, if it exists.

    If we return None, no diff is possible because the entity matches 100%, is a stub,
    or was created from a deserialized report without diff data."""
    if entity.report_diff is not None:
        return entity.report_diff

    if entity.udiff is not None:
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


#### JSON schema and conversion functions ####


@dataclass
class JSONEntityVersion1:
    # pylint:disable=too-many-instance-attributes
    address: str
    name: str
    matching: float
    comparison: dict[str, object] | None = None
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
    function_count: int | None = None


def _side_json(side: DifferenceSide) -> dict[str, object]:
    return {
        "instruction_index": side.instruction_index,
        "address": side.address,
        "facts": side.facts,
    }


def _analysis_json(analysis: ComparisonAnalysis) -> dict[str, object]:
    value: dict[str, object] = {"status": analysis.status.value}
    if analysis.effective_reasons:
        value["effective_reasons"] = list(analysis.effective_reasons)
    if analysis.difference is not None:
        value["difference"] = {
            "kind": analysis.difference.kind,
            "orig": _side_json(analysis.difference.orig),
            "recomp": _side_json(analysis.difference.recomp),
        }
    if analysis.inconclusive_reason is not None:
        value["inconclusive_reason"] = analysis.inconclusive_reason
    if analysis.inconclusive_location is not None:
        value["inconclusive_location"] = _side_json(analysis.inconclusive_location)
    return value


MAGIC_STRING_VARIOUS = "various"
"""reccmp-aggregate uses this to indicate an entity whose recomp addr varied between the sample reports."""


def _parse_side(value: object) -> DifferenceSide:
    if not isinstance(value, dict):
        raise ReccmpReportDeserializeError
    instruction_index = value.get("instruction_index")
    address = value.get("address")
    if instruction_index is not None and not isinstance(instruction_index, int):
        raise ReccmpReportDeserializeError
    if address is not None and not isinstance(address, int):
        raise ReccmpReportDeserializeError
    facts = value.get("facts", {})
    if not isinstance(facts, dict):
        raise ReccmpReportDeserializeError
    if not all(
        isinstance(key, str) and (fact is None or isinstance(fact, (str, int, bool)))
        for key, fact in facts.items()
    ):
        raise ReccmpReportDeserializeError
    return DifferenceSide(instruction_index, address, facts)


def _parse_analysis(value: object) -> ComparisonAnalysis:
    if not isinstance(value, dict):
        raise ReccmpReportDeserializeError
    try:
        status = ComparisonStatus(value["status"])
        difference_value = value.get("difference")
        difference = None
        if difference_value is not None:
            difference = ComparisonDifference(
                kind=difference_value["kind"],
                orig=_parse_side(difference_value["orig"]),
                recomp=_parse_side(difference_value["recomp"]),
            )
        return ComparisonAnalysis(
            status=status,
            effective_reasons=tuple(value.get("effective_reasons", ())),
            difference=difference,
            inconclusive_reason=value.get("inconclusive_reason"),
            inconclusive_location=(
                _parse_side(value["inconclusive_location"])
                if value.get("inconclusive_location") is not None
                else None
            ),
        )
    except (KeyError, TypeError, ValueError) as ex:
        raise ReccmpReportDeserializeError from ex


def _serialize_version_1(
    report: ReccmpStatusReport,
    diff_included: bool = False,
) -> JSONReportVersion1:
    """The JSON report can exclude the diff to make deserialization faster."""
    entities = []

    for addr, entity in report.entities.items():
        if not entity.is_matched():
            continue

        assert addr == entity.orig_addr
        entities.append(
            JSONEntityVersion1(
                address=format_address(addr),
                name=entity.name,
                matching=entity.accuracy,
                comparison=_analysis_json(entity.analysis),
                recomp=(
                    format_address(entity.recomp_addr)
                    if entity.recomp_addr is not None
                    else (MAGIC_STRING_VARIOUS if entity.recomp_addr_varies else "")
                ),
                stub=entity.is_stub,
                library=entity.is_library,
                diff=(get_udiff_for_entity(entity) if diff_included else None),
                type=int(entity.type) if entity.type is not None else None,
            )
        )

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
        try:
            entity_type = EntityType(e.type) if e.type is not None else None
        except ValueError:
            entity_type = None

        orig_addr = int(e.address, 16)

        if e.recomp == MAGIC_STRING_VARIOUS:
            recomp_addr = None
            various = True
        else:
            recomp_addr = int(e.recomp, 16) if e.recomp is not None else None
            various = False

        if e.comparison is not None:
            analysis = _parse_analysis(e.comparison)
        elif e.effective:
            raise ReccmpReportDeserializeError
        elif e.matching == 1.0:
            analysis = ComparisonAnalysis.exact()
        else:
            analysis = ComparisonAnalysis.inconclusive("analysis_limit")

        report.entities[orig_addr] = ReccmpComparedEntity(
            orig_addr=orig_addr,
            name=e.name,
            accuracy=e.matching,
            type=entity_type,
            recomp_addr=recomp_addr,
            analysis=analysis,
            is_stub=bool(e.stub),
            is_library=bool(e.library),
            udiff=e.diff,
            report_diff=e.diff,
            recomp_addr_varies=various,
        )

    report.update_function_count()
    return report


def _parse_report_diff(value: object) -> CombinedDiffOutput | None:
    """Restore the tuple-shaped in-memory diff representation from JSON lists."""
    if value is None:
        return None
    if not isinstance(value, list):
        raise ReccmpReportDeserializeError
    output: CombinedDiffOutput = []
    try:
        for group in value:
            if not isinstance(group, list) or len(group) != 2:
                raise ReccmpReportDeserializeError
            slug, blocks = group
            if not isinstance(slug, str) or not isinstance(blocks, list):
                raise ReccmpReportDeserializeError
            parsed_blocks: list[MatchingOrMismatchingBlock] = []
            for block in blocks:
                if not isinstance(block, dict):
                    raise ReccmpReportDeserializeError
                if not set(block).issubset({"both", "orig", "recomp"}):
                    raise ReccmpReportDeserializeError
                parsed_block = cast(
                    MatchingOrMismatchingBlock,
                    {
                        key: [tuple(item) for item in lines]
                        for key, lines in block.items()
                    },
                )
                parsed_blocks.append(parsed_block)
            output.append((slug, parsed_blocks))
    except (TypeError, ValueError) as ex:
        raise ReccmpReportDeserializeError from ex
    return output


def deserialize_reccmp_report(json_str: str) -> ReccmpStatusReport:
    """Read only the current structured format-1 schema."""
    try:
        obj = JSONReportVersion1.model_validate(from_json(json_str))
        return _deserialize_version_1(obj)
    except (ValidationError, ValueError) as ex:
        raise ReccmpReportDeserializeError from ex


def serialize_reccmp_report(
    report: ReccmpStatusReport,
    diff_included: bool = False,
) -> str:
    """Create a JSON string for the report so it can be written to a file."""
    obj = _serialize_version_1(report, diff_included=diff_included)

    return obj.model_dump_json(exclude_defaults=True)
