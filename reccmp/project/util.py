import hashlib
from pathlib import Path
import re
import itertools
from typing import Iterable, Iterator


def get_path_sha256(p: Path) -> str:
    sha256_hasher = hashlib.sha256()
    sha256_hasher.update(p.read_bytes())
    return sha256_hasher.hexdigest()


def path_to_id(path: Path) -> str:
    return re.sub("[^0-9a-zA-Z_]", "", path.stem.upper())


def unique_targets(paths: Iterable[Path]) -> Iterator[tuple[str, Path]]:
    """Create a unique ID for each path, starting with the base filename."""
    seen_targets = set()
    for path in paths:
        target = path_to_id(path)
        if target in seen_targets:
            for new_target in (
                f"{target}_{suffix}" for suffix in itertools.count(start=0, step=1)
            ):
                if new_target not in seen_targets:
                    target = new_target
                    break

        seen_targets.add(target)
        yield (target, path)
