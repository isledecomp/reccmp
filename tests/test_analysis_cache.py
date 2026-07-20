from pathlib import Path
from unittest.mock import patch

from reccmp.analysis_cache import (
    AnalysisCache,
    fingerprint_files,
    fingerprint_text_files,
)
from reccmp.compare.target_analysis import _load_cvdump
from reccmp.cvdump.parser import CvdumpParser
from reccmp.formats import TextFile
from reccmp.parser import DecompCodebase
from reccmp.project.detect import GhidraConfig, RecCmpTarget, ReportConfig

from .raw_image import RawImage


def test_cache_hit_and_fingerprint_invalidation(tmp_path: Path):
    cache = AnalysisCache(tmp_path / "cache")
    value = {"parsed": [1, 2, 3]}

    assert cache.load("pdb", "first") is None
    cache.store("pdb", "first", value)
    assert cache.load("pdb", "first") == value
    assert cache.load("pdb", "second") is None


def test_corrupt_cache_is_a_miss(tmp_path: Path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "pdb.pickle").write_bytes(b"not a pickle")

    assert AnalysisCache(cache_dir).load("pdb", "fingerprint") is None


def test_cache_from_removed_python_class_is_a_miss(tmp_path: Path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "pdb.pickle").write_bytes(b"placeholder")

    with patch("reccmp.analysis_cache.pickle.load", side_effect=AttributeError):
        assert AnalysisCache(cache_dir).load("pdb", "fingerprint") is None


def test_disabled_cache_does_not_write(tmp_path: Path):
    cache = AnalysisCache(tmp_path / "cache", enabled=False)
    cache.store("pdb", "fingerprint", {"value": True})

    assert cache.load("pdb", "fingerprint") is None
    assert not cache.root.exists()


def test_file_fingerprint_changes_with_contents(tmp_path: Path):
    source = tmp_path / "source.cpp"
    source.write_text("one", encoding="utf-8")
    first = fingerprint_files([source], context="parser-v1")
    source.write_text("two", encoding="utf-8")

    assert fingerprint_files([source], context="parser-v1") != first


def test_text_file_fingerprint_is_deterministic_and_contextual():
    first = TextFile(Path("a.cpp"), "// FUNCTION: TEST 0x1000")
    second = TextFile(Path("b.cpp"), "// FUNCTION: TEST 0x2000")

    expected = fingerprint_text_files([first, second], context="TEST")
    assert fingerprint_text_files([second, first], context="TEST") == expected
    assert fingerprint_text_files([first, second], context="OTHER") != expected


def test_targeted_analysis_reuses_cached_full_cvdump(tmp_path: Path):
    cache = AnalysisCache(tmp_path / "cache")
    cached = CvdumpParser()
    cache.store("cvdump-full", "pdb-fingerprint", cached)
    target = RecCmpTarget(
        target_id="TEST",
        filename="TEST.exe",
        sha256="",
        encoding="utf-8",
        source_paths=(),
        ghidra_config=GhidraConfig(),
        report_config=ReportConfig(),
        original_path=tmp_path / "TEST.exe",
        recompiled_path=tmp_path / "build" / "TEST.exe",
        recompiled_pdb=tmp_path / "build" / "TEST.pdb",
    )

    with (
        patch(
            "reccmp.compare.target_analysis.fingerprint_files",
            return_value="pdb-fingerprint",
        ),
        patch(
            "reccmp.compare.target_analysis._load_base_cvdump",
            side_effect=AssertionError("base cvdump should not be loaded"),
        ),
    ):
        result, fingerprint, scope = _load_cvdump(
            target,
            RawImage.from_memory(),
            DecompCodebase([], "TEST"),
            (0x401000,),
            (),
            cache,
            use_cache=True,
        )

    assert isinstance(result, CvdumpParser)
    assert fingerprint == "pdb-fingerprint"
    assert scope == "full"
