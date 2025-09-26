"""Testing items specific to YML parsing/pydantic validation"""

from pathlib import Path
from reccmp.project.config import ProjectFile


def test_project_without_csv():
    """Make sure we can parse a target even if the 'csv' field is not defined."""

    p = ProjectFile.from_str(
        """\
        targets:
            TEST:
                source-root: test
                hash:
                    sha256: test
                filename: test.exe
        """
    )

    assert p.targets["TEST"].data_sources == []


def test_project_with_csv_list():
    """Parse the list of csv paths."""

    p = ProjectFile.from_str(
        """\
        targets:
            TEST:
                source-root: test
                hash:
                    sha256: test
                filename: test.exe
                data-sources:
                - file0.csv
                - file1.csv
        """
    )

    assert p.targets["TEST"].data_sources == [Path("file0.csv"), Path("file1.csv")]
