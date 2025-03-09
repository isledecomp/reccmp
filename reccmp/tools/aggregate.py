#!/usr/bin/env python3

import argparse
import logging
from typing import Sequence
from pathlib import Path
from reccmp.isledecomp.utils import diff_json, write_html_report
from reccmp.isledecomp.compare.report import (
    ReccmpStatusReport,
    combine_reports,
    ReccmpReportDeserializeError,
    ReccmpReportSameSourceError,
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
        elif not path.exists():
            logger.warning("File not found: '%s'", path)

    return samples


class TwoOrMoreArgsAction(argparse.Action):
    """Support nargs=2+"""

    def __call__(
        self, parser, namespace, values: Sequence[str] | None, option_string=None
    ):
        assert isinstance(values, Sequence)
        if len(values) < 2:
            raise argparse.ArgumentError(self, "expected two or more arguments")

        setattr(namespace, self.dest, values)


class TwoOrFewerArgsAction(argparse.Action):
    """Support nargs=(1,2)"""

    def __call__(
        self, parser, namespace, values: Sequence[str] | None, option_string=None
    ):
        assert isinstance(values, Sequence)
        if len(values) not in (1, 2):
            raise argparse.ArgumentError(self, "expected one or two arguments")

        setattr(namespace, self.dest, values)


def main():
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Aggregate saved accuracy reports.",
    )
    parser.add_argument(
        "--diff",
        type=Path,
        metavar="<files>",
        nargs="+",
        action=TwoOrFewerArgsAction,
        help="Report files to diff.",
    )
    parser.add_argument(
        "--html",
        type=Path,
        metavar="<file>",
        help="Location for HTML report based on aggregate.",
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
        action=TwoOrMoreArgsAction,
        help="Report files to aggregate.",
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )

    args = parser.parse_args()

    if not (args.samples or args.diff):
        parser.error(
            "exepected arguments for --samples or --diff. (No input files specified)"
        )

    if not (args.output or args.diff or args.html):
        parser.error(
            "expected arguments for --output, --html, or --diff. (No output action specified)"
        )

    agg_report: ReccmpStatusReport | None = None

    if args.samples is not None:
        samples = deserialize_sample_files(args.samples)

        if len(samples) < 2:
            logger.error("Not enough samples to aggregate!")
            return 1

        try:
            agg_report = combine_reports(samples)
        except ReccmpReportSameSourceError:
            filename_list = sorted({s.filename for s in samples})
            logger.error(
                "Aggregate samples are not from the same source file!\nFilenames used: %s",
                filename_list,
            )
            return 1

        if args.output is not None:
            write_report_file(args.output, agg_report)

        if args.html is not None:
            write_html_report(args.html, agg_report)

    # If --diff has at least one file and we aggregated some samples this run, diff the first file and the aggregate.
    # If --diff has two files and we did not aggregate this run, diff the files in the list.
    if args.diff is not None:
        saved_data = load_report_file(args.diff[0])

        if agg_report is None:
            if len(args.diff) > 1:
                agg_report = load_report_file(args.diff[1])
            else:
                logger.error("Not enough files to diff!")
                return 1
        elif len(args.diff) == 2:
            logger.warning(
                "Ignoring second --diff argument '%s'.\nDiff of '%s' and aggregate report follows.",
                args.diff[1],
                args.diff[0],
            )

        diff_json(saved_data, agg_report, show_both_addrs=False, is_plain=args.no_color)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
