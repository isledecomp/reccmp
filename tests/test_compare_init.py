"""Testing constructors of the Compare core"""

from pathlib import Path
from unittest.mock import patch
import pytest
from reccmp.compare import Compare
from reccmp.project.detect import RecCmpTarget, GhidraConfig, ReportConfig
from reccmp.cvdump.parser import CvdumpParser
from .raw_image import RawImage


@pytest.fixture(name="source_dir")
def fixture_source_dir(tmp_path_factory) -> Path:
    """Create a basic source root with files in two directories."""
    src_dir = tmp_path_factory.mktemp("src")
    (src_dir / "hello.cpp").write_text("")
    (src_dir / "hello.hpp").write_text("")
    (src_dir / "test").mkdir()
    (src_dir / "test" / "game.cpp").write_text("")
    (src_dir / "test" / "game.hpp").write_text("")

    return src_dir


def test_nested_paths(source_dir: Path):
    """Compare core will eliminate duplicate code file paths
    if the list of source paths contains any that are nested."""
    nested_paths = (source_dir, source_dir / "test")

    target = RecCmpTarget(
        target_id="TEST",
        filename="TEST.exe",
        sha256="",
        source_paths=nested_paths,
        original_path=Path("TEST.exe"),
        recompiled_path=Path("build/TEST.exe"),
        recompiled_pdb=Path("build/TEST.pdb"),
        ghidra_config=GhidraConfig(),
        report_config=ReportConfig(),
    )

    # Patch detect_image: don't open the file, just return a RawImage
    # Patch Cvdump.run: don't subprocess.run, just return an empty Cvdump result
    with (
        patch(
            "reccmp.compare.core.detect_image", new=lambda **_: RawImage.from_memory()
        ),
        patch("reccmp.compare.core.Cvdump.run", new=lambda _: CvdumpParser()),
    ):
        c = Compare.from_target(target)

        # If path walks were just combined, we would have 6 files.
        assert len(c.code_files) == 4

        # Verify that paths are sorted
        assert [f.path.name for f in c.code_files] == [
            "hello.cpp",
            "hello.hpp",
            "game.cpp",
            "game.hpp",
        ]
