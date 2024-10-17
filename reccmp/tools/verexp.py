#!/usr/bin/env python3

import argparse
import difflib
import logging
import subprocess
import os

import reccmp
from reccmp.bin import lib_path_join
from reccmp.isledecomp.utils import print_diff
from reccmp.project.detect import (
    RecCmpProjectException,
    argparse_add_built_project_target_args,
    argparse_parse_built_project_target,
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
    argparse_add_built_project_target_args(parser)
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )
    argparse_add_logging_args(parser)

    args = parser.parse_args()

    argparse_parse_logging(args)

    try:
        target = argparse_parse_built_project_target(args)
    except RecCmpProjectException as e:
        logger.error("%s", e.args[0])
        return 1

    def get_exports(file):
        call = [lib_path_join("DUMPBIN.EXE"), "/EXPORTS"]

        if os.name != "nt":
            call.insert(0, "wine")
            file = (
                subprocess.check_output(["winepath", "-w", file])
                .decode("utf-8")
                .strip()
            )

        call.append(file)

        raw = subprocess.check_output(call).decode("utf-8").split("\r\n")
        exports = []

        start = False

        for line in raw:
            if not start:
                if line == "            ordinal hint   name":
                    start = True
            else:
                if line:
                    exports.append(line[27 : line.rindex("  (")])
                elif exports:
                    break

        return exports

    og_exp = get_exports(target.original_path)
    re_exp = get_exports(target.recompiled_path)

    udiff = difflib.unified_diff(og_exp, re_exp)
    has_diff = print_diff(udiff, args.no_color)

    return 1 if has_diff else 0


if __name__ == "__main__":
    raise SystemExit(main())
