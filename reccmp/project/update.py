import logging
from pathlib import Path
import shutil

from reccmp.assets import get_asset_file

logger = logging.getLogger(__name__)


def update_project(
    project_directory: Path,
) -> None:
    reccmp_cmake_path = project_directory / "cmake/reccmp.cmake"

    if reccmp_cmake_path.is_file():
        # Copy template CMake script that generates reccmp-build.yml
        logger.info("Copying %s...", "cmake/reccmp.cmake")
        shutil.copy(
            get_asset_file("cmake/reccmp.cmake"),
            reccmp_cmake_path,
        )
    logger.info("Done")
