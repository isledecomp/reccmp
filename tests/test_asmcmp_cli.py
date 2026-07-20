"""Command-line selection for reccmp-reccmp reports."""

from unittest.mock import patch

from reccmp.tools.asmcmp import parse_args


def test_parse_repeated_report_address_filters():
    argv = [
        "reccmp-reccmp",
        "--target",
        "TEST",
        "--orig-address",
        "0x401000",
        "--orig-address",
        "0x402000",
        "--recomp-address",
        "0x501000",
        "--no-cache",
    ]

    with patch("sys.argv", argv):
        args = parse_args()

    assert args.orig_address == [0x401000, 0x402000]
    assert args.recomp_address == [0x501000]
    assert args.no_cache
