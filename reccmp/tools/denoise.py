#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path
from reccmp.isledecomp.utils import diff_json
from reccmp.isledecomp.compare.report import (
    ReccmpStatusReport,
    combine_reports,
    ReccmpReportDeserializeError,
    deserialize_reccmp_report,
    serialize_reccmp_report,
)


logger = logging.getLogger(__name__)


def write_report_file(output_file: Path, report: ReccmpStatusReport):
    """Convert the status report to JSON and write to a file."""
    json_str = serialize_reccmp_report(report)

    with open(output_file, "w+", encoding="utf-8") as f:
        f.write(json_str)


def load_report_file(report_path: Path) -> ReccmpStatusReport:
    """Deserialize from JSON at the given filename and return the report."""

    with report_path.open("r", encoding="utf-8") as f:
        return deserialize_reccmp_report(f.read())


def deserialize_sample_files(paths: list[Path]) -> list[ReccmpStatusReport]:
    """Deserialize all sample files and return the list of reports.
    Does not remove duplicates."""
    samples = []

    for path in paths:
        if path.is_file():
            try:
                report = load_report_file(path)
                samples.append(report)
            except ReccmpReportDeserializeError:
                logger.warning("Skipping '%s' due to import error", path)

    return samples


def main():
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Aggregate saved accuracy reports.",
    )
    parser.add_argument(
        "--diff", type=Path, metavar="<files>", nargs="+", help="Report files to diff."
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        metavar="<file>",
        help="Where to save the aggregate file.",
    )
    parser.add_argument(
        "--samples",
        type=Path,
        metavar="<files>",
        nargs="+",
        help="Report files to aggregate.",
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )

    args = parser.parse_args()

    agg_report: ReccmpStatusReport | None = None

    if args.samples is not None:
        samples = deserialize_sample_files(args.samples)

        if len(samples) < 2:
            logger.error("Not enough samples to aggregate!")
            return 1

        agg_report = combine_reports(samples)

        if args.output is not None:
            write_report_file(args.output, agg_report)

    # If --diff has at least one file and we aggregated some samples this run, diff the first file and the aggregate.
    # If --diff has two or more files and we did not aggregate this run, diff the first two files in the list.
    if args.diff is not None:
        saved_data = load_report_file(args.diff[0])

        if agg_report is None:
            if len(args.diff) > 1:
                agg_report = load_report_file(args.diff[1])
            else:
                logger.error("Not enough files to diff!")
                return 1

        diff_json(saved_data, agg_report, show_both_addrs=False, is_plain=args.no_color)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
