#!/usr/bin/env python3

import argparse
import difflib
import logging
from pathlib import Path

import reccmp
from reccmp.isledecomp.formats import detect_image, PEImage
from reccmp.isledecomp.utils import print_diff
from reccmp.project.detect import (
    RecCmpProjectException,
    argparse_add_project_target_args,
    argparse_parse_project_target,
)
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Verify Exports: Compare the exports of two DLLs.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    argparse_add_project_target_args(parser)
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )
    argparse_add_logging_args(parser)

    args = parser.parse_args()

    argparse_parse_logging(args)

    try:
        target = argparse_parse_project_target(args)
    except RecCmpProjectException as e:
        logger.error("%s", e.args[0])
        return 1

    def get_exports(filepath: Path) -> list[str]:
        img = detect_image(filepath=filepath)
        if not isinstance(img, PEImage):
            raise ValueError(f"{filepath} is not a PE executable")

        return [symbol.decode("ascii") for _, symbol in img.exports]

    og_exp = get_exports(target.original_path)
    re_exp = get_exports(target.recompiled_path)

    udiff = difflib.unified_diff(og_exp, re_exp)
    has_diff = print_diff(udiff, args.no_color)

    return 1 if has_diff else 0


if __name__ == "__main__":
    raise SystemExit(main())
