import dataclasses
from pathlib import Path


@dataclasses.dataclass
class Image:
    filepath: Path
    view: memoryview = dataclasses.field(repr=False)
    data: bytes = dataclasses.field(repr=False)
