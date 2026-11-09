import struct
from bisect import bisect_left
from collections.abc import Iterator, Mapping
from types import MappingProxyType
from reccmp.formats import PEImage


def image_relocation_table(image: PEImage) -> Mapping[int, int]:
    """Read each position in the relocation table to construct the pointer map."""
    sorted_relocs = sorted(image.relocations)
    pointers = {}
    for section in image.sections:
        base = section.virtual_address
        view = section.view
        # Relocation sites in this section with four bytes of physical data.
        i = bisect_left(sorted_relocs, base)
        j = bisect_left(sorted_relocs, base + len(view) - 3)
        for site in sorted_relocs[i:j]:
            (pointers[site],) = struct.unpack_from("<I", view, site - base)

    return MappingProxyType(pointers)


def _page_code_table(destinations: list[range]) -> tuple[bytes, set[bytes]]:
    """To search for pointers into any of the provided ranges, we want to reduce the number of times
    we need to call bytes.find(). Start by collecting the possible page values (high 16-bit words)
    for the section ranges. Create a translation table to convert each byte from each word into:

        0 - not part of any page
        1 - only the low byte of a page
        2 - only the high byte of a page
        3 - either the low or high byte of a page

    Return the translation table and list of expected patterns.
    """
    pages: set[int] = set()
    for range_ in destinations:
        low_page = range_.start >> 16
        high_page = (range_.stop - 1) >> 16
        pages.update(range(low_page, high_page + 1))

    table = bytearray(256)
    for page in pages:
        table[page & 0xFF] |= 1
        table[page >> 8] |= 2

    # Only search for the patterns that actually appear.
    patterns = {bytes([table[page & 0xFF], table[page >> 8]]) for page in pages}
    return bytes(table), patterns


def _candidate_offsets(codes: bytes, patterns: set[bytes]) -> Iterator[int]:
    """Search the translated data in `codes` for any of the provided `patterns`.
    Matching offsets are potential 32-bit pointers from the original data."""
    for pattern in patterns:
        # Searching for matching high word: skip first 2 byte
        i = codes.find(pattern, 2)
        while i != -1:
            # Shift offset to include low word
            yield i - 2
            i = codes.find(pattern, i + 1)


def find_pointers(image: PEImage) -> Mapping[int, int]:
    """Map the location of each 32-bit (TODO: #573) pointer in the image to its destination.
    We do not restrict candidate addresses by their alignment.
    If the image has a relocation table, use it to read the pointer values.
    If not, search the image for pointers in any section that point to addresses in a data section.
    """
    if image.relocations:
        return image_relocation_table(image)

    # Without a relocation table, keep only pointers into data sections.
    destinations = [region.range for region in image.get_data_regions()]
    table, patterns = _page_code_table(destinations)

    pointers = {}

    # Don't search for pointers in .rsrc
    for section in [*image.get_code_regions(), *image.get_data_regions()]:
        data = bytes(section.data)
        base = section.addr
        codes = data.translate(table)
        for offset in _candidate_offsets(codes, patterns):
            # Read the real pointer from the section
            (addr,) = struct.unpack_from("<I", data, offset)

            # More granular test for whether this is a pointer to a data section.
            for range_ in destinations:
                if addr in range_:
                    pointers[base + offset] = addr
                    break

    return MappingProxyType(pointers)
