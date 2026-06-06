import argparse
import logging
import reccmp.color


def preconfigure_logging():
    logging.addLevelName(
        logging.WARNING,
        f"{reccmp.color.Fore.YELLOW}{logging.getLevelName(logging.WARNING)}{reccmp.color.Style.RESET_ALL}",
    )
    logging.addLevelName(
        logging.ERROR,
        f"{reccmp.color.Fore.RED}{logging.getLevelName(logging.ERROR)}{reccmp.color.Style.RESET_ALL}",
    )
    logging.addLevelName(
        logging.CRITICAL,
        f"{reccmp.color.Fore.RED}{logging.getLevelName(logging.CRITICAL)}{reccmp.color.Style.RESET_ALL}",
    )


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
    if hasattr(args, "no_color"):
        reccmp.color.enable_color(not args.no_color)

    preconfigure_logging()
    logging.basicConfig(level=args.loglevel, format="[%(levelname)s] %(message)s")
