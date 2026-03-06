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


def test_project_data_source_non_csv():
    """Data source filetype is not limited to .csv, even though we only parse those files at the start."""

    p = ProjectFile.from_str(
        """\
        targets:
            TEST:
                source-root: test
                hash:
                    sha256: test
                filename: test.exe
                data-sources:
                - file0.yml
                - file1.txt
        """
    )

    assert p.targets["TEST"].data_sources == [Path("file0.yml"), Path("file1.txt")]


def test_project_source_root_single():
    """source_root field: Make sure we create the Path tuple for a single value."""

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

    assert isinstance(p.targets["TEST"].source_root, tuple)
    assert p.targets["TEST"].source_root == (Path("test"),)


def test_project_source_root_multi_line_array():
    """source_root field: Make sure we create the Path tuple for a multi-line array."""

    p = ProjectFile.from_str(
        """\
        targets:
            TEST:
                source-root:
                    - test
                    - hello
                hash:
                    sha256: test
                filename: test.exe
        """
    )

    assert isinstance(p.targets["TEST"].source_root, tuple)
    assert p.targets["TEST"].source_root == (Path("test"), Path("hello"))


def test_project_source_root_inline_array():
    """source_root field: Make sure we create the Path tuple for an inline array"""

    p = ProjectFile.from_str(
        """\
        targets:
            TEST:
                source-root: ['test', 'hello']
                hash:
                    sha256: test
                filename: test.exe
        """
    )

    assert isinstance(p.targets["TEST"].source_root, tuple)
    assert p.targets["TEST"].source_root == (Path("test"), Path("hello"))


def test_project_source_root_inline_array_empty():
    """source_root field: Make sure we create an empty tuple for an empty inline array."""

    p = ProjectFile.from_str(
        """\
        targets:
            TEST:
                source-root:
                hash:
                    sha256: test
                filename: test.exe
        """
    )

    assert isinstance(p.targets["TEST"].source_root, tuple)
    assert p.targets["TEST"].source_root == ()


def test_project_source_root_missing_key():
    """source_root field: Make sure we create an empty tuple if source_root is missing."""

    p = ProjectFile.from_str(
        """\
        targets:
            TEST:
                hash:
                    sha256: test
                filename: test.exe
        """
    )

    assert isinstance(p.targets["TEST"].source_root, tuple)
    assert p.targets["TEST"].source_root == ()
