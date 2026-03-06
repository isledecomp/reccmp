"""Tests for walking source code directories in search of relevant files"""

from pathlib import Path
from reccmp.dir import walk_source_dir


def create_blank_file(p: Path):
    """Helper to make this action more idiomatic in the tests."""
    p.write_text("")


def test_empty_dir(tmp_path_factory):
    """Empty directory returns no files."""
    path = tmp_path_factory.mktemp("empty")

    files = list(walk_source_dir(path))
    assert not files


def test_dir_with_irrelevant_files(tmp_path_factory):
    """Skip files that do not match our default filter on file extension."""
    path = tmp_path_factory.mktemp("no_match")
    create_blank_file(path / "test.txt")
    create_blank_file(path / "sample.jpg")

    files = list(walk_source_dir(path))
    assert not files


def test_dir_with_mixed_files(tmp_path_factory):
    """Return code files and skip non-matching files."""
    path = tmp_path_factory.mktemp("mixed")
    create_blank_file(path / "test.txt")
    create_blank_file(path / "sample.jpg")
    create_blank_file(path / "game.cpp")
    create_blank_file(path / "game.hpp")

    files = list(walk_source_dir(path))
    assert len(files) == 2
    assert {f.name for f in files} == {"game.cpp", "game.hpp"}


def test_recursion(tmp_path_factory):
    """Should scan every subdirectory for matching files."""
    path = tmp_path_factory.mktemp("recurse")
    create_blank_file(path / "game.cpp")
    (path / "x" / "y" / "z").mkdir(parents=True)
    create_blank_file(path / "x" / "hello.cpp")
    create_blank_file(path / "x" / "y" / "z" / "test.cpp")

    files = list(walk_source_dir(path))
    assert {f.name for f in files} == {"game.cpp", "hello.cpp", "test.cpp"}


def test_recursion_disabled(tmp_path_factory):
    """Should not enter subdirectories if recursion is disabled."""
    path = tmp_path_factory.mktemp("recurse")
    create_blank_file(path / "game.cpp")
    (path / "x" / "y" / "z").mkdir(parents=True)
    create_blank_file(path / "x" / "hello.cpp")
    create_blank_file(path / "x" / "y" / "z" / "test.cpp")

    files = list(walk_source_dir(path, recursive=False))
    assert {f.name for f in files} == {"game.cpp"}


def test_absolute_paths(tmp_path_factory):
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


def test_mixed_case_extension(tmp_path_factory):
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


def test_case_insensitive_order(tmp_path_factory):
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

    files = list(walk_source_dir(path, sort=True))
    assert [f.name.lower() for f in files] == [
        "game.cpp",
        "hello.c",
        "hello.h",
        "test.hpp",
    ]
