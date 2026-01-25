from typing import NamedTuple


class DisasmLiteInst(NamedTuple):
    address: int
    size: int
    mnemonic: str
    op_str: str
