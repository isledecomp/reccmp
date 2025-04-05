"""Testing lines database: mapping between (filename, line_number) to virtual address."""

from pathlib import PurePath, PurePosixPath, PureWindowsPath
from reccmp.isledecomp.compare.lines import LinesDb

TEST_PATH = PurePath("test.cpp")


def test_lines():
    """Basic demonstration of behavior"""
    lines = LinesDb([TEST_PATH])

    # We haven't added any addresses yet.
    assert lines.search_line(TEST_PATH, 1, 10) is None

    # Test search on line 2 only
    lines.add_line(TEST_PATH, 2, 0x1234)
    assert lines.search_line(TEST_PATH, 2) == 0x1234

    # Search window
    assert lines.search_line(TEST_PATH, 1, 2) == 0x1234

    # Outside of search window
    assert lines.search_line(TEST_PATH, 1, 1) is None
    assert lines.search_line(TEST_PATH, 3, 10) is None


def test_no_files_of_interest():
    """Same as above test, but with no files declared up front.
    Calls to add_line do not alter the db."""

    lines = LinesDb([])
    lines.add_line(TEST_PATH, 2, 0x1234)
    # The address is ignored because "test.cpp" is not part of the decomp code base.
    assert lines.search_line(TEST_PATH, 2) is None


def test_multiple_match():
    """search_line looks for function starts in the range specified.
    If we find more than one address, the file does not match our data source (PDB or MAP).
    """

    # TODO: Change this when we add *all* lines instead of just known function starts.
    lines = LinesDb([TEST_PATH])
    lines.add_line(TEST_PATH, 2, 0x1234)
    lines.add_line(TEST_PATH, 3, 0x1235)

    # Both match on their own
    assert lines.search_line(TEST_PATH, 2) == 0x1234
    assert lines.search_line(TEST_PATH, 3) == 0x1235

    # Two addresses in this range of line numbers. return None.
    assert lines.search_line(TEST_PATH, 2, 3) is None


def test_db_hash_windows():
    """Our DB uses PurePath as the key, so we rely on
    the equality check for whichever platform you are running on.
    Windows paths are not case-sensitive."""

    path = PureWindowsPath("test.cpp")
    lines = LinesDb([path])
    lines.add_line(path, 2, 0x1234)

    # Should match any variation
    assert lines.search_line(path, 2) == 0x1234
    assert lines.search_line(PureWindowsPath("Test.cpp"), 2) == 0x1234
    assert lines.search_line(PureWindowsPath("TEST.CPP"), 2) == 0x1234


def test_db_hash_posix():
    """Same as above, but POSIX paths *are* case-sensitive.
    The goal here is to show that we are not taking liberties with PurePath
    and when it can be expected to match."""

    path = PurePosixPath("test.cpp")
    lines = LinesDb([path])
    lines.add_line(path, 2, 0x1234)

    # Should match only the exact path
    assert lines.search_line(path, 2) == 0x1234
    assert lines.search_line(PurePosixPath("Test.cpp"), 2) is None
    assert lines.search_line(PurePosixPath("TEST.CPP"), 2) is None
