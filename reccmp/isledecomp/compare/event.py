import enum
import logging
from typing import Protocol


class LoggingSeverity(enum.IntEnum):
    """To improve type checking. There isn't an enum to import from the logging module."""

    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR


class ReccmpEvent(enum.Enum):
    NO_MATCH = enum.auto()

    # Symbol (or designated unique attribute) was found not to be unique
    NON_UNIQUE_SYMBOL = enum.auto()

    # Match by name/type not unique
    AMBIGUOUS_MATCH = enum.auto()

    # User input (e.g. code annotation) cannot be added to the database
    INVALID_USER_DATA = enum.auto()

    # Some annotations are in an incorrect order
    WRONG_ORDER = enum.auto()

    GENERAL_WARNING = enum.auto()


def event_to_severity(event: ReccmpEvent) -> LoggingSeverity:
    return {
        ReccmpEvent.NO_MATCH: LoggingSeverity.ERROR,
        ReccmpEvent.NON_UNIQUE_SYMBOL: LoggingSeverity.WARNING,
        ReccmpEvent.AMBIGUOUS_MATCH: LoggingSeverity.WARNING,
        ReccmpEvent.INVALID_USER_DATA: LoggingSeverity.ERROR,
    }.get(event, LoggingSeverity.INFO)


class ReccmpReportProtocol(Protocol):
    def __call__(self, event: ReccmpEvent, orig_addr: int, /, msg: str = ""):
        ...


def reccmp_report_nop(*_, **__):
    """Reporting no-op function"""


def create_logging_wrapper(logger: logging.Logger) -> ReccmpReportProtocol:
    """Return a function to use when you just want to redirect events to the given logger"""

    def wrap(event: ReccmpEvent, _: int, msg: str = ""):
        logger.log(event_to_severity(event), msg)

    return wrap
