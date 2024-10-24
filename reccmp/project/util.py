import hashlib
from pathlib import Path
import re


def get_path_sha256(p: Path) -> str:
    sha256_hasher = hashlib.sha256()
    sha256_hasher.update(p.read_bytes())
    return sha256_hasher.hexdigest()


def path_to_id(path: Path) -> str:
    return re.sub("[^0-9a-zA-Z_]", "", path.stem.upper())
