import re
from bisect import bisect_left
from typing import Iterable, Iterator, NamedTuple
from reccmp.formats import PEImage

r_likely_string = re.compile(r"[\t\r\n\x20-\x7f][\t\r\n\x20-\x7f\xa0-\xff]*")


def is_likely_latin1(string) -> bool:
    """Heuristic to eliminate data streams that are not real strings.
    We exclude bytes not in the Latin1 (ISO/IEC 8859-1) character set
    and also assume the string begins with an ASCII character."""
    return r_likely_string.fullmatch(string) is not None


class StringConstant(NamedTuple):
    address: int
    value: str


def find_string_consts(
    image: PEImage, search_addrs: Iterable[int], encoding: str = "ascii"
) -> Iterator[StringConstant]:
    """In each data section of the image, at each of the provided
    addresses inside that section, test whether the address is
    the start of a string with the given encoding."""
    search_addrs = sorted(search_addrs)

    for region in image.get_data_regions():
        start = bisect_left(search_addrs, region.range.start)
        stop = bisect_left(search_addrs, region.range.stop)
        for addr in search_addrs[start:stop]:
            try:
                string = image.read_string(addr).decode(encoding)
            except UnicodeDecodeError:
                continue

            yield StringConstant(addr, string)
