"""Tests for detecting likely addresses (pointers) by inspection of the image."""

from typing import cast
from reccmp.formats import PEImage
from reccmp.analysis.pointers import find_pointers


class NoRelocations:
    """Wrapper for the `binfile` fixture to hide its relocation table."""

    relocations: set[int] = set()

    def __init__(self, image: PEImage):
        self._image = image

    def __getattr__(self, name: str):
        return getattr(self._image, name)


def test_find_pointer_returns_superset_of_real_pointers(binfile: PEImage):
    """The `binfile` fixture has a relocation table. If we hide this via mocking, then search the
    image using find_pointers(), we should detect at least what can be found from the real relocation table.
    We expect to return some false positives but not miss any real pointers.

    We currently return only the addresses that point to data sections, so this is our baseline.
    """
    data_addrs = [region.range for region in binfile.get_data_regions()]
    # If the image has a relocation table, find_pointers() will return its map.
    expected = {
        src: dst
        for src, dst in find_pointers(binfile).items()
        if any(dst in range_ for range_ in data_addrs)
    }

    found = find_pointers(cast(PEImage, NoRelocations(binfile)))

    assert expected.items() <= found.items()
