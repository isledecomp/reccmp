import re

r_likely_string = re.compile(r"([\t\r\n\x20-\x7f][\t\r\n\x20-\x7f\xa0-\xff]*)")


def is_likely_latin1(string) -> bool:
    """Heuristic to eliminate data streams that are not real strings.
    We exclude bytes not in the Latin1 (ISO/IEC 8859-1) characte set
    and also assume the string begins with an ASCII character."""
    return r_likely_string.fullmatch(string) is not None
