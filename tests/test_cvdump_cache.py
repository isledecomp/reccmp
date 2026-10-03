"""Tests for the optional on-disk cache of the cvdump.exe output."""

import json
from pathlib import Path
import pytest
from reccmp.cvdump.cache import CvdumpCache, cache_directory


@pytest.fixture(name="inputs")
def fixture_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A PDB and a cvdump.exe to key a cache entry on, and a cache directory
    of our own to keep it in."""
    monkeypatch.setenv("RECCMP_CACHE_DIR", str(tmp_path / "cache"))
    pdb = tmp_path / "test.pdb"
    pdb.write_bytes(b"pdb contents")
    exe = tmp_path / "cvdump.exe"
    exe.write_bytes(b"exe contents")
    return (pdb, exe)


def store(cache: CvdumpCache, text: str):
    with cache.writer() as write:
        write(text)


def load(cache: CvdumpCache) -> str | None:
    with cache.reader() as handle:
        return None if handle is None else handle.read()


def test_cache_directory_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("RECCMP_CACHE_DIR", str(tmp_path / "somewhere"))
    assert cache_directory() == tmp_path / "somewhere"


def test_round_trip(inputs):
    pdb, exe = inputs
    cache = CvdumpCache(pdb, ["-l", "-t"], exe)
    assert load(cache) is None, "nothing cached yet"

    store(cache, "the dump\n")
    assert load(cache) == "the dump\n"


def test_entry_is_reused_by_a_second_cache_object(inputs):
    """The point of the cache: a later run of the program finds it."""
    pdb, exe = inputs
    store(CvdumpCache(pdb, ["-l"], exe), "the dump\n")
    assert load(CvdumpCache(pdb, ["-l"], exe)) == "the dump\n"


def test_flag_order_does_not_matter(inputs):
    """The options come from a set, so the same request can arrive in any order."""
    pdb, exe = inputs
    store(CvdumpCache(pdb, ["-l", "-t"], exe), "the dump\n")
    assert load(CvdumpCache(pdb, ["-t", "-l"], exe)) == "the dump\n"


def test_different_flags_do_not_collide(inputs):
    """A dump made with other options describes something else."""
    pdb, exe = inputs
    store(CvdumpCache(pdb, ["-l"], exe), "lines only\n")
    assert load(CvdumpCache(pdb, ["-l", "-t"], exe)) is None
    assert load(CvdumpCache(pdb, ["-l"], exe)) == "lines only\n"


def test_modified_pdb_is_not_reused(inputs):
    """The whole risk of caching: serving a dump of a binary that has been
    rebuilt since."""
    pdb, exe = inputs
    cache = CvdumpCache(pdb, ["-l"], exe)
    store(cache, "the dump\n")

    pdb.write_bytes(b"pdb contents, now longer")
    assert load(cache) is None


def test_modified_cvdump_is_not_reused(inputs):
    """A different cvdump.exe may not produce the same text."""
    pdb, exe = inputs
    cache = CvdumpCache(pdb, ["-l"], exe)
    store(cache, "the dump\n")

    exe.write_bytes(b"a different build of cvdump")
    assert load(cache) is None


def test_invalidate_ignores_and_replaces(inputs):
    pdb, exe = inputs
    store(CvdumpCache(pdb, ["-l"], exe), "stale\n")

    invalidating = CvdumpCache(pdb, ["-l"], exe, invalidate=True)
    assert load(invalidating) is None, "must not serve the stale entry"
    store(invalidating, "fresh\n")

    assert load(CvdumpCache(pdb, ["-l"], exe)) == "fresh\n"


def test_one_entry_per_pdb_and_flags(inputs):
    """Rebuilding replaces the entry instead of filling the disk with dumps."""
    pdb, exe = inputs
    cache = CvdumpCache(pdb, ["-l"], exe)
    for i in range(3):
        pdb.write_bytes(b"pdb contents " + str(i).encode())
        store(cache, "dump %d\n" % i)

    assert len(list(cache_directory().iterdir())) == 1
    assert load(cache) == "dump 2\n"


def test_unreadable_entry_is_ignored(inputs):
    pdb, exe = inputs
    cache = CvdumpCache(pdb, ["-l"], exe)
    store(cache, "the dump\n")

    entry = next(cache_directory().iterdir())
    entry.write_text("this is not json\nand this is not a dump\n")
    assert load(cache) is None


def test_entry_from_another_format_version_is_ignored(inputs):
    pdb, exe = inputs
    cache = CvdumpCache(pdb, ["-l"], exe)
    store(cache, "the dump\n")

    entry = next(cache_directory().iterdir())
    lines = entry.read_text().splitlines(keepends=True)
    metadata = json.loads(lines[0])
    metadata["format"] = metadata["format"] + 1
    entry.write_text(json.dumps(metadata) + "\n" + "".join(lines[1:]))

    assert load(cache) is None


def test_interrupted_write_is_discarded(inputs):
    """A dump that was cut off would parse as a complete one, so it must not be
    kept, and it must not be left behind under a name a later run looks for."""
    pdb, exe = inputs
    cache = CvdumpCache(pdb, ["-l"], exe)

    with pytest.raises(RuntimeError):
        with cache.writer() as write:
            write("the first half of the dump\n")
            raise RuntimeError("cvdump.exe died")

    assert load(cache) is None
    assert not list(cache_directory().iterdir()), "no partial file left behind"


def test_abandoned_write_is_discarded(inputs):
    """Same, for a consumer that simply stops reading."""
    pdb, exe = inputs
    cache = CvdumpCache(pdb, ["-l"], exe)

    def partial():
        with cache.writer() as write:
            write("the first half of the dump\n")
            yield "a line"
            write("never reached\n")

    generator = partial()
    next(generator)
    generator.close()

    assert load(cache) is None
    assert not list(cache_directory().iterdir())


def test_missing_pdb_disables_the_cache(inputs):
    """We cannot key an entry on a file that is not there; say nothing is cached
    rather than failing the run."""
    pdb, exe = inputs
    pdb.unlink()
    cache = CvdumpCache(pdb, ["-l"], exe)

    store(cache, "the dump\n")
    assert load(cache) is None
