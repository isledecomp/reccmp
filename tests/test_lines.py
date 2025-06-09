"""Testing lines database: mapping between (filename, line_number) to virtual address."""

from pathlib import PurePosixPath, PureWindowsPath
import pytest
from reccmp.isledecomp.compare.lines import LinesDb

# For tests that don't require path conversion, parametrize the
# input local_path so that we test both Windows and Posix paths.
PDB_PATH = PureWindowsPath("code\\test.cpp")
LOCAL_PATHS = (
    PureWindowsPath("code\\test.cpp"),
    PurePosixPath("code/test.cpp"),
)


def test_sample_path_variables():
    """Verify PDB_PATH and LOCAL_PATHS sample values.
    Each local path should resolve to the PDB path."""
    assert PDB_PATH.parts == LOCAL_PATHS[0].parts
    assert PDB_PATH.parts == LOCAL_PATHS[1].parts


@pytest.mark.parametrize("local_path", LOCAL_PATHS)
def test_lines(local_path: PureWindowsPath | PurePosixPath):
    """Basic demonstration of behavior with a simple file path."""
    # Start by adding the local code files for our project.
    # These are the candidates for matching Windows paths from the PDB.
    lines = LinesDb([local_path])

    # No results: we haven't added any addresses yet.
    assert lines.find_function(local_path, 1, 10) is None

    # Attach line 2 of the file to this virtual address.
    # The add_line function expects a Windows-like path from the PDB.
    # All other functions use the local path.
    lines.add_line(PDB_PATH, 2, 0x1234)

    # Should return nothing: we have not marked this addr as the start of a function
    assert lines.find_function(local_path, 2) is None

    # Now we get the function
    lines.mark_function_starts((0x1234,))
    assert lines.find_function(local_path, 2) == 0x1234

    # If the range of lines overlaps with the function start, we get a match.
    assert lines.find_function(local_path, 1, 2) == 0x1234

    # If the range does not include line 2: no match.
    assert lines.find_function(local_path, 1, 1) is None
    assert lines.find_function(local_path, 3, 10) is None


@pytest.mark.parametrize("local_path", LOCAL_PATHS)
def test_no_files_of_interest(local_path: PureWindowsPath | PurePosixPath):
    """Same as above test, but with no files declared up front.
    Calls to add_line do not alter the db."""
    lines = LinesDb([])
    lines.add_line(PDB_PATH, 2, 0x1234)
    lines.mark_function_starts((0x1234,))
    # The address is ignored because "test.cpp" is not part of the decomp code base.
    assert lines.find_function(local_path, 2) is None


@pytest.mark.parametrize("local_path", LOCAL_PATHS)
def test_multiple_match(local_path: PureWindowsPath | PurePosixPath):
    """find_function looks for function starts in the range specified.
    If we find more than one address, the file does not match our data source (PDB or MAP).
    """

    lines = LinesDb([local_path])
    lines.add_line(PDB_PATH, 2, 0x1234)
    lines.add_line(PDB_PATH, 3, 0x1235)
    lines.mark_function_starts((0x1234, 0x1235))

    # Both match on their own
    assert lines.find_function(local_path, 2) == 0x1234
    assert lines.find_function(local_path, 3) == 0x1235

    # Two addresses in this range of line numbers. return None.
    assert lines.find_function(local_path, 2, 3) is None


def test_lines_duplicate_reference():
    """
    In MSVC versions as early as MSVC 7.00, the same function can be referenced on multiple lines.
    This should not cause an error to be thrown.
    """
    lines = LinesDb([TEST_PATH])
    lines.add_line(TEST_PATH, 2, 0x1234)
    lines.add_line(TEST_PATH, 4, 0x1234)
    lines.mark_function_starts((0x1234,))

    assert lines.find_function(TEST_PATH, 2, 4) == 0x1234


def test_db_hash_windows():
    """Our DB uses PurePath as the key, so we rely on
    the equality check for whichever platform you are running on.
    Windows paths are not case-sensitive."""

    local_path = PureWindowsPath("code\\test.cpp")
    lines = LinesDb([local_path])

    pdb_path = PureWindowsPath("code\\test.cpp")
    lines.add_line(pdb_path, 2, 0x1234)
    lines.mark_function_starts((0x1234,))

    # Should match any variation
    assert lines.find_function(local_path, 2) == 0x1234
    assert lines.find_function(PureWindowsPath("code\\Test.cpp"), 2) == 0x1234
    assert lines.find_function(PureWindowsPath("code\\TEST.CPP"), 2) == 0x1234
    assert lines.find_function(PureWindowsPath("Code\\test.cpp"), 2) == 0x1234


def test_db_hash_posix():
    """Same as above, but POSIX paths *are* case-sensitive.
    The goal here is to show that we are not taking liberties with PurePath
    and when it can be expected to match."""

    local_path = PurePosixPath("code/test.cpp")
    lines = LinesDb([local_path])

    pdb_path = PureWindowsPath("code\\test.cpp")
    lines.add_line(pdb_path, 2, 0x1234)
    lines.mark_function_starts((0x1234,))

    # Should match only the exact path
    assert lines.find_function(local_path, 2) == 0x1234
    assert lines.find_function(PurePosixPath("code/Test.cpp"), 2) is None
    assert lines.find_function(PurePosixPath("code/TEST.CPP"), 2) is None
    assert lines.find_function(PurePosixPath("Code/test.cpp"), 2) is None


@pytest.mark.parametrize("local_path", LOCAL_PATHS)
def test_db_search_line(local_path: PureWindowsPath | PurePosixPath):
    """search_line() will return any line in the given range
    unless you restrict to function starts only."""

    lines = LinesDb([local_path])

    # We haven't added any addresses yet.
    assert [*lines.search_line(local_path, 1, 10)] == []

    lines.add_line(PDB_PATH, 2, 0x1234)
    lines.add_line(PDB_PATH, 5, 0x2000)

    # Return single line if no end range specified
    assert [*lines.search_line(local_path, 2)] == [0x1234]
    assert [*lines.search_line(local_path, 5)] == [0x2000]

    # Test line range
    assert [*lines.search_line(local_path, 2, 4)] == [0x1234]
    assert [*lines.search_line(local_path, 2, 5)] == [0x1234, 0x2000]
    assert [*lines.search_line(local_path, 3, 5)] == [0x2000]

    # No lines marked as function starts
    assert [*lines.search_line(local_path, 2, 5, start_only=True)] == []

    lines.mark_function_starts((0x1234,))
    assert [*lines.search_line(local_path, 2, 5, start_only=True)] == [0x1234]
