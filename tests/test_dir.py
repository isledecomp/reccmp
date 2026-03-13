"""Tests for walking source code directories in search of relevant files"""

from pathlib import Path
from reccmp.dir import source_code_search, walk_source_dir


def create_blank_file(p: Path):
    """Helper to make this action more idiomatic in the tests."""
    p.write_text("")


def test_walk_empty_dir(tmp_path_factory):
    """Empty directory returns no files."""
    path = tmp_path_factory.mktemp("empty")

    files = list(walk_source_dir(path))
    assert not files


def test_walk_dir_with_irrelevant_files(tmp_path_factory):
    """Skip files that do not match our default filter on file extension."""
    path = tmp_path_factory.mktemp("no_match")
    create_blank_file(path / "test.txt")
    create_blank_file(path / "sample.jpg")

    files = list(walk_source_dir(path))
    assert not files


def test_walk_dir_with_mixed_files(tmp_path_factory):
    """Return code files and skip non-matching files."""
    path = tmp_path_factory.mktemp("mixed")
    create_blank_file(path / "test.txt")
    create_blank_file(path / "sample.jpg")
    create_blank_file(path / "game.cpp")
    create_blank_file(path / "game.hpp")

    files = list(walk_source_dir(path))
    assert len(files) == 2
    assert {f.name for f in files} == {"game.cpp", "game.hpp"}


def test_walk_non_directory(tmp_path_factory):
    """Return nothing if the input path is not a directory."""
    path = tmp_path_factory.mktemp("mixed")
    create_blank_file(path / "test.txt")
    create_blank_file(path / "sample.jpg")
    create_blank_file(path / "game.cpp")
    create_blank_file(path / "game.hpp")

    files = list(walk_source_dir(path / "game.cpp"))
    assert not files


def test_walk_recursion(tmp_path_factory):
    """Should scan every subdirectory for matching files."""
    path = tmp_path_factory.mktemp("recurse")
    create_blank_file(path / "game.cpp")
    (path / "x" / "y" / "z").mkdir(parents=True)
    create_blank_file(path / "x" / "hello.cpp")
    create_blank_file(path / "x" / "y" / "z" / "test.cpp")

    files = list(walk_source_dir(path))
    assert {f.name for f in files} == {"game.cpp", "hello.cpp", "test.cpp"}


def test_walk_recursion_disabled(tmp_path_factory):
    """Should not enter subdirectories if recursion is disabled."""
    path = tmp_path_factory.mktemp("recurse")
    create_blank_file(path / "game.cpp")
    (path / "x" / "y" / "z").mkdir(parents=True)
    create_blank_file(path / "x" / "hello.cpp")
    create_blank_file(path / "x" / "y" / "z" / "test.cpp")

    files = list(walk_source_dir(path, recursive=False))
    assert {f.name for f in files} == {"game.cpp"}


def test_walk_absolute_paths(tmp_path_factory):
    """Returned paths should be absolute and include all subdirectories."""
    path = tmp_path_factory.mktemp("recurse")
    create_blank_file(path / "game.cpp")
    (path / "x" / "y" / "z").mkdir(parents=True)
    create_blank_file(path / "x" / "hello.cpp")
    create_blank_file(path / "x" / "y" / "z" / "test.cpp")

    files = list(walk_source_dir(path))
    for f in files:
        assert f.is_absolute()

        # For files in subdirectories, make sure each one is represented.
        # Check only the components relative to the base path.
        # We don't control where pytest creates the tmp directory.
        if f.name == "hello.cpp":
            assert "x" in f.relative_to(path).parts

        if f.name == "test.cpp":
            assert "x" in f.relative_to(path).parts
            assert "y" in f.relative_to(path).parts
            assert "z" in f.relative_to(path).parts


def test_walk_mixed_case_extension(tmp_path_factory):
    """Should use case-insensitive match for file extensions."""
    path = tmp_path_factory.mktemp("mixed_case")
    create_blank_file(path / "game.CPP")
    create_blank_file(path / "HELLO.C")
    create_blank_file(path / "HELLO.h")
    create_blank_file(path / "test.hpP")

    files = list(walk_source_dir(path))
    assert {f.name.lower() for f in files} == {
        "game.cpp",
        "hello.c",
        "hello.h",
        "test.hpp",
    }


def test_search_mixed_files(tmp_path_factory):
    """Search behaves the same as walk_source_dir: return only matching code files."""
    path = tmp_path_factory.mktemp("mixed")
    create_blank_file(path / "test.txt")
    create_blank_file(path / "sample.jpg")
    create_blank_file(path / "game.cpp")
    create_blank_file(path / "game.hpp")

    files = list(source_code_search(path))
    assert {f.name for f in files} == {"game.cpp", "game.hpp"}


def test_search_ignore_missing_dir(tmp_path_factory):
    """Search should return nothing if the search path does not exist."""
    path = tmp_path_factory.mktemp("mixed")
    create_blank_file(path / "test.txt")
    create_blank_file(path / "sample.jpg")
    create_blank_file(path / "game.cpp")
    create_blank_file(path / "game.hpp")

    files = list(source_code_search(path / "x"))
    assert not files


def test_search_input_order_ignored(tmp_path_factory):
    """The returned paths are always sorted by their lower-case string version,
    regardless of input order."""
    path = tmp_path_factory.mktemp("order")
    create_blank_file(path / "game.cpp")
    create_blank_file(path / "Test.cpp")

    search_paths = (path / "Test.cpp", path / "game.cpp")
    files = list(source_code_search(search_paths))
    assert [f.name for f in files] == ["game.cpp", "Test.cpp"]


def test_search_ignore_irrelevant_file_even_if_targeted(tmp_path_factory):
    """The current behavior is to test each file's extension.
    This is true even if the input search path points directly at a file."""
    path = tmp_path_factory.mktemp("mixed")
    create_blank_file(path / "test.txt")
    create_blank_file(path / "sample.jpg")
    create_blank_file(path / "game.cpp")
    create_blank_file(path / "game.hpp")

    search_paths = path / "test.text"
    files = list(source_code_search(search_paths))
    assert not files


def test_search_nested_dirs(tmp_path_factory):
    """Should return distinct files if any search paths overlap."""
    path = tmp_path_factory.mktemp("recurse")
    create_blank_file(path / "game.cpp")
    (path / "x" / "y" / "z").mkdir(parents=True)
    create_blank_file(path / "x" / "hello.cpp")
    create_blank_file(path / "x" / "y" / "z" / "test.cpp")

    # Nested paths
    search_paths = (path, path / "x")
    files = list(source_code_search(search_paths))
    assert len(files) == 3


def test_search_using_file(tmp_path_factory):
    """Using a file as our search path, the search function
    should return the path if the file exists and matches our criteria."""
    path = tmp_path_factory.mktemp("mixed")
    create_blank_file(path / "test.txt")
    create_blank_file(path / "sample.jpg")
    create_blank_file(path / "game.cpp")
    create_blank_file(path / "game.hpp")

    files = list(source_code_search(path / "game.cpp"))
    assert [f.name for f in files] == ["game.cpp"]


def test_search_using_file_not_exist(tmp_path_factory):
    """Search should return nothing if the search path does not exist.
    Using a file in this example."""
    path = tmp_path_factory.mktemp("mixed")
    create_blank_file(path / "test.txt")
    create_blank_file(path / "sample.jpg")
    create_blank_file(path / "game.cpp")
    create_blank_file(path / "game.hpp")

    files = list(source_code_search(path / "hello.cpp"))
    assert not files


def test_search_case_insensitive_order(tmp_path_factory):
    """Make sure path order is consistent across Posix/Windows runners.
    The difference is that paths are case-sensitive on Posix but not Windows.
    The expectation is that reccmp returns the same results regardless of platform.
    Metadata read from source code files could be overwritten if it is duplicated across files.
    """
    path = tmp_path_factory.mktemp("mixed_case")
    create_blank_file(path / "game.CPP")
    create_blank_file(path / "HELLO.C")
    create_blank_file(path / "HELLO.h")
    create_blank_file(path / "test.hpP")

    files = list(source_code_search(path))
    assert [f.name.lower() for f in files] == [
        "game.cpp",
        "hello.c",
        "hello.h",
        "test.hpp",
    ]
