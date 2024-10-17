from pathlib import Path


def get_asset_file(filename: str) -> Path:
    return Path(__file__).resolve().parent / filename
