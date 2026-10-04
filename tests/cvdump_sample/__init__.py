"""Helper to load cvdump `TYPES` sample data from files in this directory.

Many tests need cvdump output to populate the types database, and the text for
the `TYPES` section can span many lines. The cvinfo key of a particular type
is also important, although it does not have any intrinsic significance.
`load_cvdump_sample` seeks to improve the situation.

Calling `load_cvdump_sample(sample_name)` will load `{sample_name}.txt` from
this directory. The dataclass returned has a list of aliases to type keys
used in the `TYPES` section text that follows.

The expected format is:
    1. Aliases and type keys separated by a single space.
       Type key in hex format with 0x prefix.
    2. Blank line.
    3. Cvdump text from TYPES section.

For example:
    alias-1 0x1000
    alias-2 0x1001

    0x1000 : Length = 10, Leaf = 0x1002 LF_POINTER
        ...
"""

from dataclasses import dataclass
from pathlib import Path
from reccmp.cvdump.cvinfo import CvdumpTypeKey

SAMPLE_DIR = Path(__file__).parent


@dataclass(frozen=True)
class CvdumpSample:
    _aliases: dict[str, CvdumpTypeKey]
    text: str

    def key(self, alias: str) -> CvdumpTypeKey:
        return self._aliases[alias]


def load_cvdump_sample(name: str) -> CvdumpSample:
    """Read a sample file from the current directory with extension `.txt`
    matching the given name. Raise any exceptions to the caller so the
    associated tests will fail."""
    contents = (SAMPLE_DIR / f"{name}.txt").read_text(encoding="utf-8")

    # Split aliases and cvdump text on the first blank line.
    alias_block, delimiter, text = contents.partition("\n\n")
    if not delimiter:
        # No blank line found: assume there are no aliases.
        return CvdumpSample({}, contents)

    aliases = {}
    for line in alias_block.splitlines():
        alias, space, key = line.partition(" ")
        if not space or " " in key:
            raise ValueError(f"Invalid alias line in sample file '{name}': {line}")

        try:
            aliases[alias] = CvdumpTypeKey(int(key, 16))
        except ValueError as ex:
            raise ValueError(f"Invalid key in sample file '{name}': {line}") from ex

    return CvdumpSample(aliases, text)
