from datetime import datetime
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator
from reccmp.types import EntityType
from .diff import CombinedDiffOutput, RawDiffOutput


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
class ReccmpReportEntity:
    # pylint:disable=too-many-instance-attributes
    orig_addr: int
    name: str
    accuracy: float
    type: EntityType
    recomp_addr: int | None = None
    """The meaning of `None` depends on `recomp_addr_varies`:
    recomp_addr_varies is False: This entity is unmatched.
    recomp_addr_varies is True:  This entity has no fixed recomp addr."""

    is_effective_match: bool = False
    is_stub: bool = False
    is_library: bool = False
    rdiff: RawDiffOutput | None = None

    # Legacy field for importing version 1 files (aggregate).
    udiff: CombinedDiffOutput | None = None

    recomp_addr_varies: bool = False
    """True if this entity had no fixed recomp address across the
    samples combined by reccmp-aggregate."""

    def is_matched(self) -> bool:
        return self.recomp_addr is not None or self.recomp_addr_varies

    def is_function(self) -> bool:
        return self.type in (EntityType.FUNCTION, EntityType.VTORDISP)

    @property
    def display_name(self) -> str:
        return self.name or f"Unnamed {self.type.name.lower()}"

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

    entities: dict[int, ReccmpReportEntity]
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
        if timestamp is not None:
            self.timestamp = timestamp
        else:
            self.timestamp = datetime.now().replace(microsecond=0)

        self.entities = {}

    def add_match(self, match: ReccmpReportEntity):
        self.entities[match.orig_addr] = match

    def has_same_source(self, other: "ReccmpStatusReport") -> bool:
        """Were both reports derived from the same reccmp target?"""
        return self.filename.lower() == other.filename.lower()

    def update_function_count(self) -> None:
        counted_type = sum(1 for ent in self.entities.values() if ent.is_function())
        self.function_count = max(self.function_count, counted_type)

    def filter_entities(self, filter_fn: Callable[[ReccmpReportEntity], bool]) -> None:
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

        def entity_filter(entity: ReccmpReportEntity) -> bool:
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
) -> Iterator[ReccmpReportEntity]:
    """Helper to return entities from xreports that have the given address."""
    for sample in samples:
        if addr in sample.entities:
            yield sample.entities[addr]


def _accuracy_sort_key(entity: ReccmpReportEntity) -> float:
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
