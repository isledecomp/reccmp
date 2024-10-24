import argparse
import logging


def argparse_add_logging_args(parser: argparse.ArgumentParser):
    parser.set_defaults(loglevel=logging.INFO)
    parser.add_argument(
        "--debug",
        action="store_const",
        const=logging.DEBUG,
        dest="loglevel",
        help="Print script debug information",
    )


def argparse_parse_logging(args: argparse.Namespace):
    logging.basicConfig(level=args.loglevel, format="[%(levelname)s] %(message)s")
