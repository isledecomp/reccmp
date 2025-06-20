"""Tests for foreign path conversion, used to resolve PDB paths from a build run on
another system or on a non-Windows host using Wine."""

from pathlib import PurePosixPath, PureWindowsPath
from reccmp.isledecomp.dir import convert_foreign_path as resolve


def test_resolve():
    # Can't do anything with no file options
    assert resolve(PureWindowsPath("Z:\\test\\file.cpp"), ()) is None

    # Match
    path = PurePosixPath("/test/file.cpp")
    assert resolve(PureWindowsPath("Z:\\test\\file.cpp"), (path,)) == path

    # Match filename only
    path = PurePosixPath("file.cpp")
    assert resolve(PureWindowsPath("Z:\\test\\file.cpp"), (path,)) == path

    # No match
    assert resolve(PureWindowsPath("Z:\\test\\file.h"), (path,)) is None

    # Match even from a different path if at least the filename matches
    path = PurePosixPath("/a/b/c/file.h")
    assert resolve(PureWindowsPath("Z:\\test\\file.h"), (path,)) == path


def test_resolve_case():
    """Match is case-insensitive, allowing for discrepancies in how the PDB
    path is presented and whether the host OS requires case match for paths."""
    # Should still match although case is different
    path = PurePosixPath("/TEST/FILE.CPP")
    assert resolve(PureWindowsPath("Z:\\test\\file.cpp"), (path,)) == path

    # Still match even if some of the parts match case
    path = PurePosixPath("/TEST/file.cpp")
    assert resolve(PureWindowsPath("Z:\\test\\file.cpp"), (path,)) == path


def test_resolve_best_match():
    """Choose the most specific match from several candidates."""
    pdb_path = PureWindowsPath("Z:\\test\\src\\core\\game.cpp")
    # Two options for "game.cpp"
    path = PurePosixPath("/Users/test/src/core/game.cpp")
    path2 = PurePosixPath("/Users/test/game.cpp")
    # Should pick the one that matches more path components
    assert resolve(pdb_path, (path, path2)) == path


def test_resolve_many_options():
    """Should return None if there are multiple equally likely options."""
    pdb_path = PureWindowsPath("Z:\\test\\game.cpp")
    # Two options for "game.cpp"
    path = PurePosixPath("xyz/test/game.cpp")
    path2 = PurePosixPath("abc/test/game.cpp")
    # Should pick the one that matches more path components
    assert resolve(pdb_path, (path, path2)) is None


def test_resolve_relative():
    """Can still match a relative path"""
    pdb_path = PureWindowsPath("core\\game.cpp")
    path = PurePosixPath("/files/core/game.cpp")
    assert resolve(pdb_path, (path,)) == path
