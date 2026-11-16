from pydantic import ValidationError
from pydantic_core import from_json
from .internal import (
    ReccmpReportEntity,
    ReccmpReportDeserializeError,
    ReccmpReportSameSourceError,
    ReccmpStatusReport,
    combine_reports,
    format_address,
    report_function_accuracy,
    report_function_alignment,
)
from .version1 import (
    JSONReportVersion1,
    _deserialize_version_1,
    _serialize_version_1,
)


def deserialize_reccmp_report(json_str: str) -> ReccmpStatusReport:
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
