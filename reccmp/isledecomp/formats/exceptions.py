class SectionNotFoundError(KeyError):
    """The specified section was not found in the file."""


class InvalidVirtualAddressError(IndexError):
    """The given virtual address is too high or low
    to point to something in the binary file."""


class InvalidVirtualReadError(IndexError):
    """Reading the given number of bytes from the given virtual address
    would cause us to read past the end of the section or past the end
    of the virtual address space."""
