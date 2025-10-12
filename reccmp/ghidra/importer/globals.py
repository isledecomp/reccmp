from dataclasses import dataclass, field
from .statistics import Statistics


@dataclass
class Globals:
    # statistics
    statistics: Statistics = field(default_factory=Statistics)


# hard-coded settings that we don't want to prompt in Ghidra every time
GLOBALS = Globals()
