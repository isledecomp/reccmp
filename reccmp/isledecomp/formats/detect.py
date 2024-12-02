from pathlib import Path

from .elf import ElfImage
from .image import Image
from .lx import LXImage
from .macho import MachOImage
from .mz import ImageDosHeader, MZImage
from .pe import PEImage


def detect_image(filepath: Path) -> Image:
    with filepath.open("rb") as f:
        data = f.read()
    if MZImage.taste(data, offset=0):
        mz_header, _ = ImageDosHeader.from_memory(data, offset=0)

        match data[mz_header.e_lfanew : mz_header.e_lfanew + 2]:
            case b"PE":
                return PEImage.from_memory(data, mz_header=mz_header, filepath=filepath)
            case b"LE":
                return LXImage.from_memory(data, mz_header=mz_header, filepath=filepath)
            case b"NE":
                raise NotImplementedError("NE file format not implemented")
            case b"NX":
                raise NotImplementedError("NX file format not implemented")
            case _:
                return MZImage.from_memory(data, mz_header=mz_header, filepath=filepath)
    if ElfImage.taste(data, offset=0):
        return ElfImage.from_memory(data, offset=0, filepath=filepath)
    if MachOImage.taste(data, offset=0):
        return MachOImage.from_memory(data, offset=0, filepath=filepath)

    raise ValueError("Unknown file format")
