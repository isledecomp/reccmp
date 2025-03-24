"""Testing command-line input for the reccmp-aggregate tool."""
import pytest
from reccmp.tools.aggregate import parse_args


def test_args_none():
    """Should fail without required params"""
    with pytest.raises(SystemExit):
        parse_args([])


def test_args_diff():
    """The --diff option requires:
    1. Two report files to compare
    2. One report file and 2 or more samples"""
    parse_args(["--diff", "A.json", "B.json"])
    parse_args(["--diff", "A.json", "--samples", "X.json", "Y.json"])

    # Can also save HTML or JSON output
    parse_args(
        ["--diff", "A.json", "--samples", "X.json", "Y.json", "--html", "report.html"]
    )
    parse_args(
        ["--diff", "A.json", "--samples", "X.json", "Y.json", "--output", "report.json"]
    )


def test_args_diff_not_enough_files():
    """Cannot diff zero files.
    Cannot diff one file if no samples are provided."""
    with pytest.raises(SystemExit):
        parse_args(["--diff"])

    with pytest.raises(SystemExit):
        parse_args(["--diff", "A.json"])

    with pytest.raises(SystemExit):
        parse_args(["--diff", "--samples", "X.json", "Y.json"])


def test_args_diff_two_files():
    """The second diff file will be ignored if --samples is used. Non-fatal error."""
    parse_args(["--diff", "A.json", "B.json", "--samples", "X.json", "Y.json"])


def test_args_diff_three_plus_files():
    """Fail if more than two files are provided for --diff. We would never use files 3-N."""
    with pytest.raises(SystemExit):
        parse_args(
            ["--diff", "A.json", "B.json", "C.json", "--samples", "X.json", "Y.json"]
        )


def test_args_samples():
    """The --samples option requires two or more sample files, and:
    1. A saved report to diff against (--diff)
    2. At least one output format (--html or --output)"""
    parse_args(["--diff", "A.json", "--samples", "X.json", "Y.json"])
    parse_args(["--samples", "X.json", "Y.json", "--html", "report.html"])
    parse_args(["--samples", "X.json", "Y.json", "--output", "report.json"])


def test_args_samples_no_output():
    """Fail if no diff file or output formats provided."""
    with pytest.raises(SystemExit):
        parse_args(["--samples", "X.json", "Y.json"])


def test_args_samples_not_enough():
    """Fail with zero or one samples"""
    with pytest.raises(SystemExit):
        parse_args(["--diff", "A.json", "--samples"])

    with pytest.raises(SystemExit):
        parse_args(["--diff", "A.json", "--samples", "X.json"])


def test_args_samples_from_file(tmp_path):
    """Confirm we can load sample list from a file.
    This is possible for any argument but --samples is the primary use case."""
    tmp_file = tmp_path / "args.txt"
    files = ["X.json", "Y.json", "Z.json"]
    tmp_file.write_text("\n".join(files), encoding="utf-8")
    args = parse_args(["--diff", "A.json", "--samples", f"@{tmp_file}"])

    assert len(args.samples) == 3

    # Get base filename from these pathlib.Path objects
    assert [path.name for path in args.samples] == files
