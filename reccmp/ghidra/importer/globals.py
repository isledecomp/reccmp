import logging
from dataclasses import dataclass, field
from .statistics import Statistics


@dataclass
class Globals:
    verbose: bool
    loglevel: int
    # TODO: Add a more permanent solution here.
    # For example: A custom function prefix per target that defaults to `FUN`
    target_name: str = "LEGO1.DLL"
    running_from_ghidra: bool = False
    # statistics
    statistics: Statistics = field(default_factory=Statistics)


# hard-coded settings that we don't want to prompt in Ghidra every time
GLOBALS = Globals(
    verbose=False,
    # loglevel=logging.INFO,
    loglevel=logging.DEBUG,
)
