from pathlib import Path
from pydantic import BaseModel


class DaemonReady(BaseModel):
    ready: bool
    target: str
    recompiled: Path
