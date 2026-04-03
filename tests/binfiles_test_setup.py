from typing import NamedTuple
from .constants import LEGO1_SHA256, SKI_SHA256, ISLE_SHA256


class TestBinfile(NamedTuple):
    filename: str
    hash_str: str


BINFILE_LEGO1 = TestBinfile("LEGO1.DLL", LEGO1_SHA256)
"""LEGO1.DLL: v1.1 English, September"""

BINFILE_SKI = TestBinfile("SKI.EXE", SKI_SHA256)
"""SkiFree 1.0, https://ski.ihoc.net/"""

BINFILE_ISLE = TestBinfile("ISLE.EXE", ISLE_SHA256)
"""ISLE.EXE: v1.1 English, September"""
