class SectionNotFoundError(KeyError):
    """The specified section was not found in the file."""


class InvalidVirtualAddressError(IndexError):
    """The given virtual address is too high or low
    to point to something in the binary file."""
