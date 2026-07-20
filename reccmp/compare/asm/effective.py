"""Relational effective-match verifier.

Decides whether two same-length sequences of sanitized assembly lines are
semantically equivalent modulo compiler entropy: register allocation,
swapped commutative operands, and inverted-condition compare/jump pairs.

The two instruction streams are executed in lockstep with a symbolic value
for every register, flag state and x87 stack slot on each side. Registers
never appear inside values; a value records *how* it was computed
(loads, arithmetic, call results...). Renaming a register therefore has no
effect on the values that flow through the function. Equivalence is judged
on the observable effects of each instruction pair:

  * memory stores (address, width and stored value must agree),
  * call targets,
  * branch conditions (canonicalized, so `cmp a, b; jg` equals
    `cmp b, a; jl`) and branch displacements,
  * the returned value in eax (or st(0) for x87 returns).

Commutative operations (add, and, or, xor, imul, test, fadd, fmul) sort
their operand values, so operand-order entropy cancels out.

Anything the model does not understand is handled conservatively: an
unsupported instruction is only allowed when its text is identical on both
sides *and* the two symbolic states are fully synchronized; otherwise the
whole function is rejected (not an effective match).
"""

from __future__ import annotations

# pylint: disable=too-many-lines

import hashlib
import re
from dataclasses import dataclass, field
from functools import cache
from typing import Callable

from reccmp.compare.diagnosis import AnalysisRecorder
from reccmp.compare.asm.instgen import InstructionMeta

# A symbolic value. Nested tuples of str/int; compared structurally.
Value = tuple


class Reject(Exception):
    """The two sequences could not be proven equivalent."""


# Register families. Writing e.g. `al` produces a new value for the whole
# `a` family so that partial-register writes are never lost.
REGISTERS: dict[str, tuple[str, str]] = {
    **{f"e{r}x": (r, "r32") for r in "abcd"},
    **{f"{r}x": (r, "r16") for r in "abcd"},
    **{f"{r}l": (r, "l8") for r in "abcd"},
    **{f"{r}h": (r, "h8") for r in "abcd"},
    "esi": ("si", "r32"),
    "si": ("si", "r16"),
    "edi": ("di", "r32"),
    "di": ("di", "r16"),
    "ebp": ("bp", "r32"),
    "bp": ("bp", "r16"),
    "esp": ("sp", "r32"),
    "sp": ("sp", "r16"),
}

FAMILIES = ("a", "b", "c", "d", "si", "di", "bp", "sp")

MEM_RE = re.compile(
    r"^(?:(byte|word|dword|qword|tbyte|xword|xmmword) ptr )?"
    r"(?:(cs|ds|es|fs|gs|ss):)?\[(.+)\]$"
)
SCALED_REG_RE = re.compile(r"^(e[a-d]x|e[sd]i|e[bs]p)\*([1248])$")
NUM_RE = re.compile(r"^-?(?:0x[0-9a-f]+|\d+)$")
ST_RE = re.compile(r"^st(?:\((\d)\))?$")

COMMUTATIVE_BINOPS = {"add", "and", "or", "xor", "imul"}
ASSOCIATIVE_COMMUTATIVE_BINOPS = {"add"}
ORDERED_BINOPS = {"sub", "shl", "shr", "sar", "rol", "ror"}
CARRY_BINOPS = {"adc", "sbb"}

# jcc/setcc condition codes with their operand-swap counterpart for
# a `cmp`-produced flag state. eq/ne are symmetric under a swap.
CC_CANON = {
    "e": ("eq", False),
    "ne": ("ne", False),
    "l": ("lt_s", False),
    "g": ("lt_s", True),
    "le": ("le_s", False),
    "ge": ("le_s", True),
    "b": ("lt_u", False),
    "a": ("lt_u", True),
    "be": ("le_u", False),
    "ae": ("le_u", True),
}

X87_CONSTANTS = {"fld1", "fldz", "fldpi", "fldl2e", "fldl2t", "fldlg2", "fldln2"}
X87_UNARY = {"fchs", "fabs", "fsqrt", "frndint", "fcos", "fsin", "ftan", "f2xm1"}


def _vsort(a: Value, b: Value) -> tuple[Value, Value]:
    """Canonical order for the operands of a commutative operation."""
    return (a, b) if repr(a) <= repr(b) else (b, a)


def _commutative_result(mnemonic: str, a: Value, b: Value) -> Value:
    """Canonicalize a commutative integer result.

    Integer addition is associative modulo the destination width, so flatten
    nested additions before sorting their leaves.  Flags and carry are kept as
    binary expressions by execute(): reassociation can change the flags from
    the final physical add even when the destination value is equal.
    """
    if mnemonic not in ASSOCIATIVE_COMMUTATIVE_BINOPS:
        return (mnemonic, *_vsort(a, b))

    terms: list[Value] = []
    pending = [a, b]
    while pending:
        value = pending.pop()
        if isinstance(value, tuple) and value and value[0] == mnemonic:
            pending.extend(value[1:])
        else:
            terms.append(value)
    return (mnemonic, *sorted(terms, key=repr))


@dataclass
class X87Stack:
    # known[0] is st(0). Slots below the known region belong to the caller
    # (or to a callee's float return) and are addressed by (epoch, index).
    known: list[Value] = field(default_factory=list)
    deep_pops: int = 0
    epoch: int = 0

    def read(self, i: int) -> Value:
        if i < len(self.known):
            return self.known[i]
        return ("fdeep", self.epoch, self.deep_pops + i - len(self.known))

    def push(self, value: Value) -> None:
        # The physical x87 stack has 8 slots; deeper is an overflow.
        if len(self.known) >= 8:
            raise Reject
        self.known.insert(0, value)

    def pop(self) -> None:
        if self.known:
            self.known.pop(0)
        else:
            self.deep_pops += 1

    def write(self, i: int, value: Value) -> None:
        if i < len(self.known):
            self.known[i] = value
        else:
            # Writing into the unknown region cannot be modeled.
            raise Reject

    def state_key(self) -> tuple:
        return (tuple(self.known), self.deep_pops, self.epoch)


@dataclass
class SideState:
    # pylint: disable=too-many-instance-attributes
    regs: dict[str, Value] = field(
        default_factory=lambda: {f: ("init", f) for f in FAMILIES}
    )
    flags: Value = ("init", "flags")
    fpu_flags: Value = ("init", "fpuflags")
    # The carry flag is tracked separately from the other integer flags:
    # inc/dec preserve CF while rewriting the rest, so a single combined
    # flag value would let e.g. `cmp a, b; inc ecx; adc ...` erase a
    # CF difference introduced by swapped cmp operands.
    carry: Value = ("init", "carry")
    x87: X87Stack = field(default_factory=X87Stack)
    # Frame-slot alpha-renaming: negative ebp displacements are replaced by
    # slot ids assigned in first-use order, so the two sides may lay out
    # their locals differently. Validated by _slots_consistent at the end.
    slot_map: dict[int, int | None] = field(default_factory=dict)
    slot_accesses: list[tuple[int, int | None]] = field(default_factory=list)
    slots_escaped: bool = False
    rename_slots: bool = True

    def slot_ref(self, disp: int, size: str, write: bool) -> Value | int:
        """Canonical key for a frame-local access. A slot becomes renamable
        only when its first access is a write (a proper lifetime start);
        a slot that is read first would let two different uninitialized
        locals appear equal, so it keeps its raw displacement."""
        self.slot_accesses.append((disp, _WIDTHS.get(size)))
        if disp not in self.slot_map:
            if write:
                self.slot_map[disp] = sum(
                    1 for v in self.slot_map.values() if v is not None
                )
            else:
                self.slot_map[disp] = None
        slot = self.slot_map[disp]
        return disp if slot is None else ("slot", slot)

    def read_reg(self, name: str) -> Value:
        family, part = REGISTERS[name]
        value = self.regs[family]
        if part == "r32":
            return value
        # Reading back the part that was just inserted yields that value.
        if isinstance(value, tuple) and value and value[0] == "ins_" + part:
            return value[2]
        return (part, value)

    def write_reg(self, name: str, value: Value) -> None:
        family, part = REGISTERS[name]
        if part == "r32":
            self.regs[family] = value
            return
        old = self.regs[family]
        # Overwriting the same part again: the previous insertion is dead.
        if isinstance(old, tuple) and old and old[0] == "ins_" + part:
            old = old[1]
        self.regs[family] = ("ins_" + part, old, value)


_WIDTHS = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "tbyte": 10}


@dataclass(frozen=True)
class CallAbi:
    """Which registers a callee reads as arguments. Derived from the PDB
    calling convention: cdecl/stdcall use neither, thiscall reads ecx,
    fastcall reads ecx and edx."""

    uses_ecx: bool
    uses_edx: bool


@dataclass(frozen=True)
class FunctionMetadata:
    """Optional PDB-derived facts that widen what the verifier can prove.

    return_kind: how the compared function returns its result —
    "void" (eax is dead at ret), "i8"/"i16" (only al/ax matter),
    "i32", "i64" (edx:eax), "float" (st0), or "unknown" (exact eax).

    call_abi: resolves a sanitized call-target name to the callee's
    register-argument usage; None means unknown (compare ecx and edx)."""

    return_kind: str = "unknown"
    call_abi: Callable[[str], CallAbi | None] | None = None


@dataclass
class Context:
    # pylint: disable=too-many-instance-attributes
    gen: int | Value = 0  # memory generation, shared by both sides
    bump_requested: bool = False
    # Every symbolic node (including subexpressions) of every expression
    # that was proven equal across the two sides. Divergent register values
    # are only excused when they appear in this set (they were consumed by
    # something matched). matched_ids memoizes the DAG walk by identity.
    matched_nodes: set[Value] = field(default_factory=set)
    matched_ids: set[int] = field(default_factory=set)
    # Memoization for _tree_size, keyed by object identity. The keepalive
    # list pins the measured tuples so their ids cannot be recycled.
    size_cache: dict[int, int] = field(default_factory=dict)
    keepalive: list = field(default_factory=list)
    # When not None, every memory access performed by execute() is recorded
    # here as ("r"|"w", address value, width, is_stack_slot).
    trace: list | None = None
    # Pending callee-save register substitutions: mutable records
    # [orig family, recomp family, stack slot address, still_valid].
    # A potentially aliasing write to the slot clears still_valid.
    save_stack: list[list] = field(default_factory=list)
    # Which acceptance features fired, for debug/audit logging.
    categories: set[str] = field(default_factory=set)
    # PDB-derived return-type and callee-convention facts, if available.
    metadata: FunctionMetadata | None = None
    # Structured evidence sink for the current verifier strategy.
    recorder: AnalysisRecorder | None = None

    def add_matched(self, value) -> None:
        stack = [value]
        while stack:
            node = stack.pop()
            if not isinstance(node, tuple):
                continue
            key = id(node)
            if key in self.matched_ids:
                continue
            self.matched_ids.add(key)
            self.keepalive.append(node)
            self.matched_nodes.add(node)
            stack.extend(node)


def _bump_linear_memory(ctx: Context) -> None:
    """Advance the integer generation used by the lockstep verifier."""
    if not isinstance(ctx.gen, int):
        raise Reject
    ctx.gen += 1


# Symbolic values are DAGs (a register value can feed several later values),
# but comparison and repr expand them to trees. Reject a function once any
# tracked value grows beyond this tree size: pathological shapes like a long
# `add eax, eax` doubling chain would otherwise take exponential time.
VALUE_SIZE_LIMIT = 50_000


def _tree_size(value, ctx: Context) -> int:
    if not isinstance(value, tuple):
        return 1
    key = id(value)
    cached = ctx.size_cache.get(key)
    if cached is not None:
        return cached
    size = 1 + sum(_tree_size(child, ctx) for child in value)
    ctx.size_cache[key] = size
    ctx.keepalive.append(value)
    return size


def guard_state_size(state: SideState, ctx: Context) -> None:
    for value in (*state.regs.values(), state.flags, state.carry, state.fpu_flags):
        if _tree_size(value, ctx) > VALUE_SIZE_LIMIT:
            raise Reject
    for value in state.x87.known:
        if _tree_size(value, ctx) > VALUE_SIZE_LIMIT:
            raise Reject


# ---------------------------------------------------------------------------
# Parsing of sanitized instruction text


def split_operands(op_str: str) -> list[str]:
    """Split on top-level ', ' only: brackets and parens may contain commas."""
    operands = []
    depth = 0
    start = 0
    i = 0
    while i < len(op_str):
        char = op_str[i]
        if char in "[(":
            depth += 1
        elif char in "])":
            depth -= 1
        elif depth == 0 and op_str.startswith(", ", i):
            operands.append(op_str[start:i])
            start = i + 2
            i += 2
            continue
        i += 1
    operands.append(op_str[start:])
    return [op for op in (o.strip() for o in operands) if op]


def parse_operand(text: str):
    if text in REGISTERS:
        return ("reg", text)

    st_match = ST_RE.match(text)
    if st_match:
        return ("st", int(st_match.group(1) or 0))

    if NUM_RE.match(text):
        return ("imm", int(text, 0))

    mem_match = MEM_RE.match(text)
    if mem_match:
        size, seg, content = mem_match.groups()
        reg_terms: list[tuple[str, int]] = []
        disp = 0
        syms: list[tuple[int, str]] = []
        tokens = re.split(r" ([+-]) ", content)
        sign = 1
        for k, token in enumerate(tokens):
            if k % 2 == 1:
                sign = 1 if token == "+" else -1
                continue
            token = token.strip()
            if token in REGISTERS:
                if sign < 0:
                    raise Reject
                reg_terms.append((token, 1))
            elif (scaled := SCALED_REG_RE.match(token)) is not None:
                if sign < 0:
                    raise Reject
                reg_terms.append((scaled.group(1), int(scaled.group(2))))
            elif NUM_RE.match(token):
                disp += sign * int(token, 0)
            else:
                syms.append((sign, token))
        return ("mem", size or "", seg or "", reg_terms, disp, tuple(sorted(syms)))

    # Symbol, placeholder, or anything else we treat as an opaque token.
    return ("sym", text)


@dataclass(frozen=True)
class Instruction:
    mnemonic: str
    prefix: str  # rep/repe/repne or ""
    operands: tuple
    raw_operands: tuple[str, ...]


def parse_instruction(line: str) -> Instruction:
    mnemonic, _, op_str = line.partition(" ")
    prefix = ""
    if mnemonic in ("rep", "repe", "repne"):
        prefix = mnemonic
        mnemonic, _, op_str = op_str.partition(" ")
    raw = tuple(split_operands(op_str)) if op_str else ()
    return Instruction(mnemonic, prefix, tuple(parse_operand(t) for t in raw), raw)


def _clean_symbol(text: str) -> str:
    """Sanitized symbol without the display-only entity annotation."""
    return re.sub(r"\s+\((?:DATA|STRING|FLOAT|FUNCTION|IMPORT)\)$", "", text)


def _symbolic_summary(value, depth: int = 0) -> str:
    # pylint: disable=too-many-return-statements
    """Small stable rendering for diagnosis; never expands the whole DAG."""
    if not isinstance(value, tuple) or not value:
        return str(value)
    tag = str(value[0])
    if tag == "imm" and len(value) > 1:
        return str(value[1])
    if tag == "sym" and len(value) > 1:
        return _clean_symbol(str(value[1]))
    if tag == "init" and len(value) > 1:
        return f"initial:{value[1]}"
    if tag == "load" and len(value) > 1:
        return f"load:{_symbolic_summary(value[1], depth + 1)}"
    if tag == "mem" and len(value) >= 5:
        symbols = value[4]
        if symbols:
            return _clean_symbol(str(symbols[0][1]))
        terms = value[2]
        base = _symbolic_summary(terms[0][0], depth + 1) if terms else "absolute"
        return f"{base}{int(value[3]):+d}"
    if depth >= 1:
        return tag
    children = [
        _symbolic_summary(child, depth + 1)
        for child in value[1:3]
        if isinstance(child, tuple)
    ]
    return f"{tag}:{','.join(children)}" if children else tag


def _symbolic_fingerprint(value) -> str:
    """Bounded deterministic identity for two values with the same summary."""
    digest = hashlib.blake2s(digest_size=4)
    pending = [value]
    visited = 0
    while pending and visited < 256:
        node = pending.pop()
        visited += 1
        if isinstance(node, tuple):
            digest.update(f"tuple:{len(node)}:".encode())
            pending.extend(reversed(node))
        else:
            digest.update(f"{type(node).__name__}:{node!s}:".encode())
    if pending:
        digest.update(b"truncated")
    return digest.hexdigest()


def _diagnostic_summaries(value_o, value_r) -> tuple[str, str]:
    """Readable summaries, disambiguated when shortening hides a difference."""
    summary_o = _symbolic_summary(value_o)
    summary_r = _symbolic_summary(value_r)
    if value_o != value_r and summary_o == summary_r:
        summary_o += f"#{_symbolic_fingerprint(value_o)}"
        summary_r += f"#{_symbolic_fingerprint(value_r)}"
    return summary_o, summary_r


def _memory_facts(op) -> dict[str, str | int | bool | None]:
    """Primitive address components from one parsed memory operand."""
    if op[0] != "mem":
        return {
            "base_register": None,
            "index_register": None,
            "scale": 1,
            "displacement": 0,
            "symbol": None,
        }
    reg_terms = op[3]
    base = next((reg for reg, scale in reg_terms if scale == 1), None)
    index = next((reg for reg, scale in reg_terms if reg != base or scale != 1), None)
    index_scale = next((scale for reg, scale in reg_terms if reg == index), 1)
    symbols = op[5]
    symbol = None
    if symbols:
        symbol = " + ".join(
            ("-" if sign < 0 else "") + _clean_symbol(str(name))
            for sign, name in symbols
        )
    return {
        "base_register": base,
        "index_register": index,
        "scale": index_scale,
        "displacement": op[4],
        "symbol": symbol,
    }


def _target_facts(
    ins: Instruction, meta: InstructionMeta | None, target_index: int | None = None
) -> dict[str, str | int | bool | None]:
    target_name = None
    if ins.raw_operands:
        raw = ins.raw_operands[0]
        if not raw.startswith(("0x", "-0x")):
            target_name = _clean_symbol(raw)
    return {
        "target": meta.branch_target if meta is not None else None,
        "target_name": target_name,
        "target_instruction_index": target_index,
    }


def _target_index(
    recorder: AnalysisRecorder | None,
    which: str,
    meta: InstructionMeta | None,
) -> int | None:
    if recorder is None or meta is None or meta.branch_target is None:
        return None
    addrs = recorder.orig_addrs if which == "orig" else recorder.recomp_addrs
    if addrs is None:
        return None
    try:
        return addrs.index(meta.branch_target)
    except ValueError:
        return None


def _checked_call_registers(ctx: Context, ins: Instruction) -> list[str]:
    abi = None
    if ctx.metadata is not None and ctx.metadata.call_abi is not None:
        if ins.operands and ins.operands[0][0] == "sym":
            abi = ctx.metadata.call_abi(ins.operands[0][1])
    registers = []
    if abi is None or abi.uses_ecx:
        registers.append("ecx")
    if abi is None or abi.uses_edx:
        registers.append("edx")
    return registers


def _record_operand_candidate(
    ctx: Context,
    index_o: int,
    index_r: int,
    ins_o: Instruction,
    ins_r: Instruction,
) -> None:
    recorder = ctx.recorder
    if recorder is None or ins_o.mnemonic != ins_r.mnemonic:
        return
    if ins_o.mnemonic in JCC_MNEMONICS or ins_o.mnemonic.startswith("loop"):
        return
    for op_o, op_r in zip(ins_o.operands, ins_r.operands):
        if op_o == op_r:
            continue
        if op_o[0] == op_r[0] == "mem":
            facts_o, facts_r = _memory_facts(op_o), _memory_facts(op_r)
            if facts_o != facts_r:
                recorder.record_difference(
                    "memory_address",
                    index_o,
                    index_r,
                    facts_o,
                    facts_r,
                    candidate=True,
                )
                return
        if op_o[0] == op_r[0] == "imm":
            recorder.record_difference(
                "immediate_value",
                index_o,
                index_r,
                {"value": op_o[1]},
                {"value": op_r[1]},
                candidate=True,
            )
            return
        if op_o[0] == op_r[0] == "sym":
            recorder.record_difference(
                "symbol_resolution",
                index_o,
                index_r,
                {"symbol": _clean_symbol(str(op_o[1]))},
                {"symbol": _clean_symbol(str(op_r[1]))},
                candidate=True,
            )
            return


def _record_observable_difference(
    ctx: Context,
    index_o: int,
    index_r: int,
    ins_o: Instruction,
    ins_r: Instruction,
    obs_o: list,
    obs_r: list,
    meta_o: InstructionMeta | None,
    meta_r: InstructionMeta | None,
) -> None:
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    # pylint: disable=too-many-return-statements
    """Classify the first differing observable at a trusted paired point."""
    recorder = ctx.recorder
    if recorder is None or recorder.difference is not None:
        return
    first_o: tuple = obs_o[0] if obs_o else ()
    first_r: tuple = obs_r[0] if obs_r else ()
    tag_o = first_o[0] if first_o else None
    tag_r = first_r[0] if first_r else None

    if tag_o == tag_r == "call":
        if first_o[1] != first_r[1]:
            recorder.record_difference(
                "call_target",
                index_o,
                index_r,
                _target_facts(ins_o, meta_o),
                _target_facts(ins_r, meta_r),
            )
            return
        registers = _checked_call_registers(ctx, ins_o)
        for position, register in enumerate(registers, start=2):
            if first_o[position] != first_r[position]:
                value_o, value_r = _diagnostic_summaries(
                    first_o[position], first_r[position]
                )
                recorder.record_difference(
                    "call_argument",
                    index_o,
                    index_r,
                    {
                        "register": register,
                        "value": value_o,
                    },
                    {
                        "register": register,
                        "value": value_r,
                    },
                )
                return

    if tag_o == tag_r == "store":
        if first_o[1] != first_r[1]:
            facts_o = _memory_facts(ins_o.operands[0]) if ins_o.operands else {}
            facts_r = _memory_facts(ins_r.operands[0]) if ins_r.operands else {}
            recorder.record_difference(
                "memory_address", index_o, index_r, facts_o, facts_r
            )
            return
        if first_o[3] != first_r[3]:
            value_o, value_r = _diagnostic_summaries(first_o[3], first_r[3])
            recorder.record_difference(
                "memory_value",
                index_o,
                index_r,
                {"value": value_o},
                {"value": value_r},
            )
            return

    branch_tags = CONTROL_TAGS - {"jmpind"}
    if tag_o in branch_tags and tag_r in branch_tags:
        predicate_o = first_o[1] if tag_o == "branch" else None
        predicate_r = first_r[1] if tag_r == "branch" else None
        if predicate_o != predicate_r:
            value_o, value_r = _diagnostic_summaries(predicate_o, predicate_r)
            recorder.record_difference(
                "branch_condition",
                index_o,
                index_r,
                {"predicate": value_o},
                {"predicate": value_r},
            )
            return
        target_o = _target_index(recorder, "orig", meta_o)
        target_r = _target_index(recorder, "recomp", meta_r)
        recorder.record_difference(
            "branch_target",
            index_o,
            index_r,
            _target_facts(ins_o, meta_o, target_o),
            _target_facts(ins_r, meta_r, target_r),
        )
        return

    for entry_o, entry_r in zip(obs_o, obs_r):
        if entry_o == entry_r:
            continue
        if entry_o and entry_r and entry_o[0] == entry_r[0]:
            if entry_o[0] in ("retval", "retfpu"):
                value_o, value_r = _diagnostic_summaries(entry_o[1], entry_r[1])
                recorder.record_difference(
                    "return_value",
                    index_o,
                    index_r,
                    {"value": value_o},
                    {"value": value_r},
                )
                return
            if entry_o[0] in ("retsaved", "retstack"):
                value_o, value_r = _diagnostic_summaries(entry_o, entry_r)
                recorder.record_difference(
                    "preserved_state",
                    index_o,
                    index_r,
                    {"value": value_o},
                    {"value": value_r},
                )
                return
    recorder.mark_inconclusive("analysis_limit")


# ---------------------------------------------------------------------------
# Symbolic execution of one side


def mem_address(
    state: SideState, op, escape: bool = False, write: bool = False
) -> Value:
    # pylint: disable=too-many-boolean-expressions
    _, size, seg, reg_terms, disp, syms = op
    disp_key: Value | int = disp
    if (
        state.rename_slots
        and not seg
        and not syms
        and disp < 0
        and any(reg == "ebp" for reg, _ in reg_terms)
        and _stack_rooted(state.regs["bp"])
    ):
        if not escape and reg_terms == [("ebp", 1)]:
            # A plain frame-local slot: alpha-renamable across the sides.
            disp_key = state.slot_ref(disp, size, write)
        else:
            # The slot's address escapes (lea) or the access is indexed
            # (a local array): renaming frame slots is no longer safe.
            state.slots_escaped = True
    terms = tuple(
        sorted(
            ((state.read_reg(reg), scale) for reg, scale in reg_terms),
            key=repr,
        )
    )
    if escape and any(_stack_rooted(value) for value, _ in terms):
        # A stack address escapes into a register: pointers derived from it
        # could reach frame slots or saved registers on the stack.
        state.slots_escaped = True
    return ("mem", seg, terms, disp_key, syms)


def read_operand(state: SideState, ctx: Context, op) -> Value:
    kind = op[0]
    if kind == "reg":
        return state.read_reg(op[1])
    if kind == "imm":
        return ("imm", op[1])
    if kind == "sym":
        return ("sym", op[1])
    if kind == "st":
        return state.x87.read(op[1])
    if kind == "mem":
        address = mem_address(state, op)
        if ctx.trace is not None:
            ctx.trace.append(("r", address, _WIDTHS.get(op[1]), False))
        return ("load", address, op[1], ctx.gen)
    raise Reject


def write_operand(state: SideState, ctx: Context, op, value: Value, obs: list) -> None:
    kind = op[0]
    if kind == "reg":
        state.write_reg(op[1], value)
    elif kind == "mem":
        address = mem_address(state, op, write=True)
        if ctx.trace is not None:
            ctx.trace.append(("w", address, _WIDTHS.get(op[1]), False))
        obs.append(("store", address, op[1], value))
        ctx.bump_requested = True
    elif kind == "st":
        state.x87.write(op[1], value)
    else:
        raise Reject


def _mul_registers(op) -> tuple[str, str]:
    """Accumulator/high register pair for single-operand mul/imul/div/idiv,
    depending on the operand width."""
    width = op[1] if op[0] == "mem" else REGISTERS[op[1]][1]
    if width in ("byte", "l8", "h8"):
        return "al", "ah"
    if width in ("word", "r16"):
        return "ax", "dx"
    return "eax", "edx"


def esp_add(value: Value, delta: int) -> Value:
    if isinstance(value, tuple) and value[0] == "spadd":
        base, offset = value[1], value[2] + delta
        return base if offset == 0 else ("spadd", base, offset)
    return ("spadd", value, delta)


# Condition codes whose outcome depends on the carry flag.
CF_CONDITIONS = frozenset({"b", "ae", "a", "be"})


def canon_condition(cc: str, state: SideState) -> Value:
    """Canonical predicate for a condition code applied to a flag state, so
    that `cmp a, b` + jg equals `cmp b, a` + jl."""
    flags = state.flags
    entry = CC_CANON.get(cc)
    if entry is not None and isinstance(flags, tuple) and flags[0] == "cmp":
        pred, swap = entry
        a, b = flags[1], flags[2]
        if pred in ("eq", "ne"):
            return (pred, _vsort(a, b))
        return (pred, b, a) if swap else (pred, a, b)
    if cc in CF_CONDITIONS:
        # The carry flag may have a different (older) producer than the
        # rest of the flags.
        return ("cc", cc, flags, state.carry)
    return ("cc", cc, flags)


JCC_MNEMONICS = {
    "ja": "a",
    "jae": "ae",
    "jb": "b",
    "jbe": "be",
    "je": "e",
    "jne": "ne",
    "jg": "g",
    "jge": "ge",
    "jl": "l",
    "jle": "le",
    "js": "s",
    "jns": "ns",
    "jo": "o",
    "jno": "no",
    "jp": "p",
    "jnp": "np",
}

STRING_OPS = {
    # mnemonic: (registers read, registers written, writes memory)
    **{f"movs{s}": ("si di", "si di", True) for s in "bwd"},
    **{f"stos{s}": ("a di", "di", True) for s in "bwd"},
    **{f"lods{s}": ("a si", "a si", False) for s in "bwd"},
    **{f"scas{s}": ("a di", "di", False) for s in "bwd"},
    **{f"cmps{s}": ("si di", "si di", False) for s in "bwd"},
}


def execute(
    state: SideState, ctx: Context, idx: int, ins: Instruction, obs: list
) -> None:
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-branches,too-many-statements
    mnemonic = ins.mnemonic
    ops = ins.operands
    value: Value

    if mnemonic == "mov" and len(ops) == 2:
        write_operand(state, ctx, ops[0], read_operand(state, ctx, ops[1]), obs)
    elif mnemonic in ("movsx", "movzx") and len(ops) == 2:
        src = ops[1]
        width = src[1] if src[0] == "mem" else REGISTERS[src[1]][1]
        value = (mnemonic, width, read_operand(state, ctx, src))
        write_operand(state, ctx, ops[0], value, obs)
    elif mnemonic == "lea" and len(ops) == 2 and ops[1][0] == "mem":
        write_operand(
            state, ctx, ops[0], ("addr", mem_address(state, ops[1], escape=True)), obs
        )
    elif mnemonic == "xchg" and len(ops) == 2:
        a = read_operand(state, ctx, ops[0])
        b = read_operand(state, ctx, ops[1])
        write_operand(state, ctx, ops[0], b, obs)
        write_operand(state, ctx, ops[1], a, obs)
    elif mnemonic in COMMUTATIVE_BINOPS and len(ops) == 2:
        a = read_operand(state, ctx, ops[0])
        b = read_operand(state, ctx, ops[1])
        pair = _vsort(a, b)
        if mnemonic == "xor" and a == b:
            value = ("imm", 0)
        else:
            value = _commutative_result(mnemonic, a, b)
        write_operand(state, ctx, ops[0], value, obs)
        state.flags = ("flags", mnemonic, *pair)
        # and/or/xor clear CF; add/imul produce a carry-out.
        if mnemonic in ("and", "or", "xor"):
            state.carry = ("cf0",)
        else:
            state.carry = ("carry", mnemonic, *pair)
    elif mnemonic == "imul" and len(ops) == 3:
        value = (
            "imul3",
            read_operand(state, ctx, ops[1]),
            read_operand(state, ctx, ops[2]),
        )
        write_operand(state, ctx, ops[0], value, obs)
        state.flags = ("flags", *value)
        state.carry = ("carry", *value)
    elif mnemonic in ORDERED_BINOPS and len(ops) == 2:
        a = read_operand(state, ctx, ops[0])
        b = read_operand(state, ctx, ops[1])
        value = ("imm", 0) if (mnemonic == "sub" and a == b) else (mnemonic, a, b)
        write_operand(state, ctx, ops[0], value, obs)
        state.flags = ("flags", mnemonic, a, b)
        # The borrow out of sub is the unsigned comparison of its operands.
        state.carry = ("lt_u", a, b) if mnemonic == "sub" else ("carry", mnemonic, a, b)
    elif mnemonic in CARRY_BINOPS and len(ops) == 2:
        a = read_operand(state, ctx, ops[0])
        b = read_operand(state, ctx, ops[1])
        value = (mnemonic, a, b, state.carry)
        write_operand(state, ctx, ops[0], value, obs)
        state.flags = ("flags", *value)
        state.carry = ("carry", *value)
    elif mnemonic in ("inc", "dec", "neg", "not") and len(ops) == 1:
        value = (mnemonic, read_operand(state, ctx, ops[0]))
        write_operand(state, ctx, ops[0], value, obs)
        # inc/dec rewrite the flags but preserve CF; not touches nothing.
        if mnemonic != "not":
            state.flags = ("flags", *value)
        if mnemonic == "neg":
            state.carry = ("carry", *value)
    elif mnemonic == "cmp" and len(ops) == 2:
        a = read_operand(state, ctx, ops[0])
        b = read_operand(state, ctx, ops[1])
        state.flags = ("cmp", a, b)
        state.carry = ("lt_u", a, b)
    elif mnemonic == "test" and len(ops) == 2:
        state.flags = (
            "test",
            *_vsort(read_operand(state, ctx, ops[0]), read_operand(state, ctx, ops[1])),
        )
        state.carry = ("cf0",)
    elif mnemonic in ("mul", "imul") and len(ops) == 1:
        acc, hi = _mul_registers(ops[0])
        pair = _vsort(state.read_reg(acc), read_operand(state, ctx, ops[0]))
        state.write_reg(acc, (mnemonic, "lo", *pair))
        state.write_reg(hi, (mnemonic, "hi", *pair))
        state.flags = ("flags", mnemonic, *pair)
        state.carry = ("carry", mnemonic, *pair)
    elif mnemonic in ("div", "idiv") and len(ops) == 1:
        acc, hi = _mul_registers(ops[0])
        divisor = read_operand(state, ctx, ops[0])
        dividend = (state.read_reg(hi), state.read_reg(acc))
        state.write_reg(acc, (mnemonic, "quot", dividend, divisor))
        state.write_reg(hi, (mnemonic, "rem", dividend, divisor))
        state.flags = ("undef_flags", idx)
        state.carry = ("undef_cf", idx)
    elif mnemonic == "cdq":
        state.write_reg("edx", ("cdq", state.read_reg("eax")))
    elif mnemonic == "cwde":
        state.write_reg("eax", ("cwde", state.read_reg("ax")))
    elif mnemonic == "sahf":
        state.flags = ("sahf", state.read_reg("ah"))
        state.carry = ("sahf_cf", state.read_reg("ah"))
    elif mnemonic == "push" and len(ops) == 1:
        value = read_operand(state, ctx, ops[0])
        new_esp = esp_add(state.read_reg("esp"), -4)
        state.write_reg("esp", new_esp)
        if ctx.trace is not None:
            ctx.trace.append(("w", new_esp, 4, "push"))
        obs.append(("store", new_esp, "stack", value))
        ctx.bump_requested = True
    elif mnemonic == "pop" and len(ops) == 1:
        esp = state.read_reg("esp")
        if ctx.trace is not None:
            ctx.trace.append(("r", esp, 4, "pop"))
        write_operand(state, ctx, ops[0], ("load", esp, "stack", ctx.gen), obs)
        state.write_reg("esp", esp_add(esp, 4))
    elif mnemonic == "leave":
        ebp = state.read_reg("ebp")
        if ctx.trace is not None:
            ctx.trace.append(("r", ebp, 4, "pop"))
        state.write_reg("ebp", ("load", ebp, "stack", ctx.gen))
        state.write_reg("esp", esp_add(ebp, 4))
    elif mnemonic == "call" and len(ops) == 1:
        # The callee may take arguments in ecx (thiscall) or ecx+edx
        # (fastcall). When per-callsite convention data from the PDB is
        # available and says a register is unused, its (dead) value need
        # not match; otherwise it must match exactly.
        abi = None
        if ctx.metadata is not None and ctx.metadata.call_abi is not None:
            if ops[0][0] == "sym":
                abi = ctx.metadata.call_abi(ops[0][1])
        entry = ["call", read_operand(state, ctx, ops[0])]
        if abi is None or abi.uses_ecx:
            entry.append(state.read_reg("ecx"))
        if abi is None or abi.uses_edx:
            entry.append(state.read_reg("edx"))
        obs.append(tuple(entry))
        for reg in ("eax", "ecx", "edx"):
            state.write_reg(reg, ("callret", idx, reg))
        state.write_reg("esp", ("callesp", idx))
        state.flags = ("callflags", idx)
        state.carry = ("callcf", idx)
        state.x87 = X87Stack(epoch=idx + 1)
        ctx.bump_requested = True
    elif mnemonic == "ret":
        obs.append(("retstack", ins.raw_operands, state.x87.state_key()[1:]))
        # Externally observable machine state at return must match exactly:
        # the callee-saved registers, the stack pointer, and the return
        # value as determined by the function's return kind. Without
        # return-type metadata from the PDB, eax must match exactly.
        obs.append(
            (
                "retsaved",
                tuple(state.regs[f] for f in ("b", "si", "di", "bp", "sp")),
            )
        )
        kind = ctx.metadata.return_kind if ctx.metadata is not None else "unknown"
        if kind == "void":
            pass
        elif kind == "float":
            obs.append(("retfpu", state.x87.read(0)))
        elif kind == "i8":
            obs.append(("retval", state.read_reg("al")))
        elif kind == "i16":
            obs.append(("retval", state.read_reg("ax")))
        elif kind == "i64":
            obs.append(("retval", state.read_reg("eax"), state.read_reg("edx")))
        elif state.x87.known:
            # x87 return value: st(0) must match; eax is scratch.
            obs.append(("retfpu", state.x87.known[0]))
        else:
            obs.append(("retval", state.read_reg("eax")))
    elif mnemonic in JCC_MNEMONICS and len(ops) == 1:
        pred = canon_condition(JCC_MNEMONICS[mnemonic], state)
        obs.append(("branch", pred, ins.raw_operands[0]))
    elif mnemonic == "jmp" and len(ops) == 1:
        if ops[0][0] == "mem":
            obs.append(("jmpind", read_operand(state, ctx, ops[0])))
        else:
            obs.append(("jmp", ins.raw_operands[0]))
    elif mnemonic in ("loop", "loope", "loopne", "jcxz", "jecxz") and len(ops) == 1:
        obs.append((mnemonic, state.read_reg("ecx"), state.flags, ins.raw_operands[0]))
        if mnemonic.startswith("loop"):
            state.write_reg("ecx", ("loopdec", state.read_reg("ecx")))
    elif mnemonic.startswith("set") and mnemonic[3:] in CC_CANON and len(ops) == 1:
        pred = canon_condition(mnemonic[3:], state)
        write_operand(state, ctx, ops[0], ("setcc", pred), obs)
    elif mnemonic.startswith("cmov") and mnemonic[4:] in JCC_MNEMONICS.values():
        pred = canon_condition(mnemonic[4:], state)
        value = (
            "cmov",
            pred,
            read_operand(state, ctx, ops[0]),
            read_operand(state, ctx, ops[1]),
        )
        write_operand(state, ctx, ops[0], value, obs)
    elif mnemonic in STRING_OPS:
        reads, writes, writes_memory = STRING_OPS[mnemonic]
        key = (mnemonic, ins.prefix)
        observed = [key]
        for family in reads.split():
            observed.append(state.regs[family])
        if ins.prefix:
            observed.append(state.regs["c"])
        obs.append(tuple(observed))
        for family in writes.split():
            state.regs[family] = ("strres", idx, family)
        if ins.prefix:
            state.regs["c"] = ("strres", idx, "c")
        if mnemonic.startswith(("scas", "cmps")):
            state.flags = ("strflags", idx)
            state.carry = ("strcf", idx)
        if writes_memory:
            ctx.bump_requested = True
    elif mnemonic in ("nop", "int3"):
        pass
    elif mnemonic.startswith("f"):
        execute_x87(state, ctx, ins, obs)
    else:
        raise Reject


def execute_x87(state: SideState, ctx: Context, ins: Instruction, obs: list) -> None:
    # pylint: disable=too-many-branches,too-many-statements
    mnemonic = ins.mnemonic
    ops = ins.operands
    x87 = state.x87

    if mnemonic in ("fld", "fild") and len(ops) == 1:
        x87.push(read_operand(state, ctx, ops[0]))
    elif mnemonic in X87_CONSTANTS and not ops:
        x87.push(("fconst", mnemonic))
    elif mnemonic in ("fst", "fstp", "fist", "fistp") and len(ops) == 1:
        value = x87.read(0)
        if mnemonic.startswith("fist"):
            value = ("fist", value)
        write_operand(state, ctx, ops[0], value, obs)
        if mnemonic.endswith("p"):
            x87.pop()
    elif mnemonic in ("fadd", "fmul", "faddp", "fmulp", "fiadd", "fimul"):
        op = "f" + ("add" if "add" in mnemonic else "mul")
        if mnemonic in ("faddp", "fmulp"):
            dest = ops[0][1] if ops else 1
            value = (op, *_vsort(x87.read(dest), x87.read(0)))
            x87.write(dest, value)
            x87.pop()
        elif len(ops) == 2 and ops[0] == ("st", 0):
            x87.write(0, (op, *_vsort(x87.read(0), x87.read(ops[1][1]))))
        elif len(ops) == 2 and ops[1] == ("st", 0):
            dest = ops[0][1]
            x87.write(dest, (op, *_vsort(x87.read(dest), x87.read(0))))
        elif len(ops) == 1:
            x87.write(0, (op, *_vsort(x87.read(0), read_operand(state, ctx, ops[0]))))
        else:
            raise Reject
    elif (
        mnemonic in ("fsub", "fsubr", "fdiv", "fdivr", "fisub", "fidiv")
        and len(ops) == 1
    ):
        op = "fsub" if "sub" in mnemonic else "fdiv"
        other = read_operand(state, ctx, ops[0])
        if mnemonic.endswith("r"):
            x87.write(0, (op, other, x87.read(0)))
        else:
            x87.write(0, (op, x87.read(0), other))
    elif mnemonic in ("fsubp", "fsubrp", "fdivp", "fdivrp"):
        op = "fsub" if "sub" in mnemonic else "fdiv"
        dest = ops[0][1] if ops else 1
        if "r" in mnemonic[4:]:
            value = (op, x87.read(0), x87.read(dest))
        else:
            value = (op, x87.read(dest), x87.read(0))
        x87.write(dest, value)
        x87.pop()
    elif mnemonic in X87_UNARY and not ops:
        x87.write(0, (mnemonic, x87.read(0)))
    elif mnemonic == "fxch":
        i = ops[0][1] if ops else 1
        a, b = x87.read(0), x87.read(i)
        x87.write(0, b)
        x87.write(i, a)
    elif mnemonic in ("fcom", "fcomp", "fucom", "fucomp", "ficom", "ficomp"):
        other = read_operand(state, ctx, ops[0]) if ops else x87.read(1)
        state.fpu_flags = ("fcom", x87.read(0), other)
        if mnemonic.endswith("p"):
            x87.pop()
    elif mnemonic in ("fcompp", "fucompp"):
        state.fpu_flags = ("fcom", x87.read(0), x87.read(1))
        x87.pop()
        x87.pop()
    elif mnemonic == "ftst":
        state.fpu_flags = ("fcom", x87.read(0), ("imm", 0))
    elif mnemonic == "fnstsw" and ops == (("reg", "ax"),):
        state.write_reg("ax", ("fsw", state.fpu_flags))
    elif mnemonic == "fnstcw" and len(ops) == 1:
        write_operand(state, ctx, ops[0], ("fcw",), obs)
    elif mnemonic == "fldcw" and len(ops) == 1:
        # Loading the control word affects rounding of subsequent operations;
        # the loaded value flows in via a checked channel only if it differs.
        obs.append(("fldcw", read_operand(state, ctx, ops[0])))
    elif mnemonic in ("fprem", "fscale"):
        x87.write(0, (mnemonic, x87.read(0), x87.read(1)))
    elif mnemonic in ("fpatan", "fyl2x"):
        value = (mnemonic, x87.read(0), x87.read(1))
        x87.pop()
        x87.write(0, value)
    else:
        raise Reject


# ---------------------------------------------------------------------------
# Lockstep driver

# Non-executable lines emitted by the sanitizer (jump/data tables).
DATA_LINE_RE = re.compile(r"^(Jump table:|Data table:|start \+ |0x[0-9a-f]+$)")


def fully_synced(orig: SideState, recomp: SideState) -> bool:
    return (
        orig.regs == recomp.regs
        and orig.flags == recomp.flags
        and orig.carry == recomp.carry
        and orig.fpu_flags == recomp.fpu_flags
        and orig.x87.state_key() == recomp.x87.state_key()
        # An unsupported-but-identical instruction accesses the same textual
        # frame slots on both sides, so any slot renaming so far must be
        # the identity for the states to be concretely identical.
        and orig.slot_map == recomp.slot_map
    )


def resync(states: tuple[SideState, SideState], idx: int, ctx: Context) -> None:
    """After an unsupported-but-identical instruction on a fully synced
    state, both sides are still concretely identical, but we no longer know
    which locations the instruction wrote. Give every location a fresh
    paired value so no stale claims survive."""
    for state in states:
        for family in FAMILIES:
            state.regs[family] = ("resync", idx, family)
        state.flags = ("resync_flags", idx)
        state.carry = ("resync_cf", idx)
        state.fpu_flags = ("resync_fpuflags", idx)
        state.x87.known = [("resync_st", idx, i) for i in range(len(state.x87.known))]
    ctx.bump_requested = True


def _contained(value: Value, ctx: Context) -> bool:
    return value in ctx.matched_nodes


def _dead_or_contained(value: Value, ctx: Context) -> bool:
    return _is_scratch(value) or _contained(value, ctx)


def _ins_split_ok(value_o: Value, value_r: Value, ctx: Context) -> bool:
    """A 16/8-bit result inserted into dead upper bits on both sides:
    the inserted part must be identical; the surrounding old bits are
    garbage as long as they came from consumed computations."""
    return (
        isinstance(value_o, tuple)
        and isinstance(value_r, tuple)
        and len(value_o) == 3
        and len(value_r) == 3
        and value_o[0] == value_r[0]
        and str(value_o[0]).startswith("ins_")
        and value_o[2] == value_r[2]
        and _dead_or_contained(value_o[1], ctx)
        and _dead_or_contained(value_r[1], ctx)
    )


# Caller-saved register families: dead at function end (eax is separately
# checked as the return value at every `ret`).
CALLER_SAVED = ("a", "c", "d")

# Observable tags of instructions that may transfer control locally.
CONTROL_TAGS = frozenset(
    {"branch", "jmp", "jmpind", "loop", "loope", "loopne", "jcxz", "jecxz"}
)


def _divergences_justified(ctx: Context, orig: SideState, recomp: SideState) -> bool:
    """At a control transfer, the current state escapes the linear flow.
    Every divergent register or x87 slot must already be justified: proven
    equal (consumed by a matched expression), inserted-part equal, or
    untouched scratch. A later overwrite on the fallthrough path must not
    be allowed to hide a real divergence that a jump path can observe."""
    for family in FAMILIES:
        value_o, value_r = orig.regs[family], recomp.regs[family]
        if value_o == value_r:
            continue
        if _ins_split_ok(value_o, value_r, ctx):
            continue
        for value in (value_o, value_r):
            if _is_scratch(value):
                continue
            if not _contained(value, ctx):
                return False
    if len(orig.x87.known) != len(recomp.x87.known):
        return False
    for slot_o, slot_r in zip(orig.x87.known, recomp.x87.known):
        if slot_o != slot_r:
            if not (_contained(slot_o, ctx) and _contained(slot_r, ctx)):
                return False
    return True


def _is_scratch(value: Value) -> bool:
    """Values with no computational content: the untouched initial register
    value, or the clobbered result of a call or string instruction. If such
    a value is left in a caller-saved register while the other side holds
    something else, the register is simply dead."""
    return (
        isinstance(value, tuple)
        and bool(value)
        and value[0]
        in (
            "init",
            "callret",
            "strres",
            "resync",
        )
    )


CALLEE_SAVED = ("b", "si", "di")


def _aligned_indices(
    codes, orig_len: int, recomp_len: int
) -> list[tuple[int | None, int | None]] | None:
    """Pair up the two sequences (by index) for lockstep verification.
    Without diff opcodes, the sequences must have equal length. With them,
    unmatched insertions/deletions become one-sided entries, which the
    verifier only accepts for whitelisted unobservable instructions."""
    if codes is None:
        if orig_len != recomp_len:
            return None
        return [(i, i) for i in range(orig_len)]
    result: list[tuple[int | None, int | None]] = []
    for tag, i1, i2, j1, j2 in codes:
        if tag in ("equal", "replace"):
            paired = min(i2 - i1, j2 - j1)
            result.extend(zip(range(i1, i1 + paired), range(j1, j1 + paired)))
            result.extend((i, None) for i in range(i1 + paired, i2))
            result.extend((None, j) for j in range(j1 + paired, j2))
        elif tag == "delete":
            result.extend((i, None) for i in range(i1, i2))
        elif tag == "insert":
            result.extend((None, j) for j in range(j1, j2))
    return result


# Mnemonics with implicit memory or environment effects that capstone's
# operand list does not surface. Never stepped over via metadata.
_META_STEP_BLACKLIST = frozenset(
    {
        "xlatb",
        "pusha",
        "pushal",
        "pushad",
        "popa",
        "popal",
        "popad",
        "pushf",
        "pushfd",
        "popf",
        "popfd",
        "enter",
        "leave",
        "int",
        "int1",
        "int3",
        "into",
        "syscall",
        "sysenter",
        "iret",
        "iretd",
        "cpuid",
        "rdtsc",
        "in",
        "out",
        "hlt",
    }
)


def _meta_step(orig: SideState, recomp: SideState, meta, idx: int) -> bool:
    """Step both sides over an identical instruction outside the symbolic
    model, using capstone's structured facts about it. Sound only when the
    instruction touches nothing but registers and flags: every register it
    reads must be cross-equal, and every register it writes gets a fresh
    paired value. Anything with memory access, control flow, x87, or
    unmapped registers falls back to the full-synchronization rule."""
    # pylint: disable=too-many-return-statements,too-many-boolean-expressions
    if (
        meta.accesses_memory
        or meta.is_jump
        or meta.is_call
        or meta.is_ret
        or meta.mnemonic in _META_STEP_BLACKLIST
        or meta.mnemonic.startswith(("f", "rep"))
    ):
        return False

    read_families: set[str] = set()
    written_families: set[str] = set()
    for names, families in (
        (meta.regs_read, read_families),
        (meta.regs_written, written_families),
    ):
        for name in names:
            if name == "eflags":
                continue
            if name not in REGISTERS:
                # x87/MMX/SSE or segment registers: not modeled.
                return False
            family, part = REGISTERS[name]
            families.add(family)
            if part != "r32" and families is written_families:
                # A partial-register write preserves the remaining bits,
                # so the family must already agree for the fresh paired
                # value to be sound.
                read_families.add(family)

    for family in read_families:
        if orig.regs[family] != recomp.regs[family]:
            return False
    if meta.reads_flags and (orig.flags != recomp.flags or orig.carry != recomp.carry):
        return False

    for family in written_families:
        value = ("metastep", idx, family)
        orig.regs[family] = value
        recomp.regs[family] = value
    if meta.writes_flags:
        orig.flags = recomp.flags = ("metastep_flags", idx)
        orig.carry = recomp.carry = ("metastep_cf", idx)

    return True


def _one_sided_ok(state: SideState, ctx: Context, idx: int, line: str) -> bool:
    """Execute an instruction that exists on only one side. Only a strict
    whitelist of provably unobservable, non-faulting instructions is
    allowed: nop, register-to-register mov, and lea (which computes an
    address without accessing memory). Anything that touches memory, the
    stack, x87, or that may trap is a real difference."""
    if DATA_LINE_RE.match(line):
        return False
    try:
        ins = parse_instruction(line)
    except (Reject, IndexError, KeyError, ValueError, TypeError):
        return False
    ops = ins.operands
    allowed = (
        ins.mnemonic == "nop"
        or (
            ins.mnemonic == "mov"
            and len(ops) == 2
            and ops[0][0] == "reg"
            and ops[1][0] == "reg"
        )
        or (
            ins.mnemonic == "lea"
            and len(ops) == 2
            and ops[0][0] == "reg"
            and ops[1][0] == "mem"
        )
    )
    if not allowed:
        return False
    obs: list = []
    try:
        execute(state, ctx, idx, ins, obs)
        guard_state_size(state, ctx)
    except (Reject, IndexError, KeyError, ValueError, TypeError):
        return False
    ctx.categories.add("dead_operation")
    return not obs


def _callee_save_swap(ctx: Context, ins_o, ins_r, obs_o, obs_r, orig, recomp) -> bool:
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    # pylint: disable=too-many-boolean-expressions
    """Detect a balanced callee-save substitution: one side saves and
    restores e.g. esi where the other uses edi. The pushed values are the
    untouched initial registers, so the stores differ; treat the pair as
    bookkeeping and make the matching pops restore the initial values."""
    if ins_o.mnemonic != ins_r.mnemonic:
        return False
    if (
        ins_o.mnemonic == "push"
        and len(obs_o) == 1
        and len(obs_r) == 1
        and obs_o[0][0] == obs_r[0][0] == "store"
        and obs_o[0][1] == obs_r[0][1]
        and obs_o[0][3][0] == obs_r[0][3][0] == "init"
        and obs_o[0][3][1] in CALLEE_SAVED
        and obs_r[0][3][1] in CALLEE_SAVED
        and obs_o[0][3] != obs_r[0][3]
    ):
        ctx.save_stack.append([obs_o[0][3][1], obs_r[0][3][1], obs_o[0][1], True])
        ctx.categories.add("callee_save_substitution")
        return True
    if (
        ins_o.mnemonic == "pop"
        and ctx.save_stack
        and ins_o.operands
        and ins_r.operands
        and ins_o.operands[0][0] == "reg"
        and ins_r.operands[0][0] == "reg"
    ):
        family_o = REGISTERS[ins_o.operands[0][1]][0]
        family_r = REGISTERS[ins_r.operands[0][1]][0]
        saved_o, saved_r, slot_addr, valid = ctx.save_stack[-1]
        popped_o = orig.regs.get(family_o)
        popped_r = recomp.regs.get(family_r)
        if (
            (saved_o, saved_r) == (family_o, family_r)
            and valid
            # A frame address that escaped could have reached the saved
            # slot through a pointer we cannot see.
            and not orig.slots_escaped
            and not recomp.slots_escaped
            and isinstance(popped_o, tuple)
            and popped_o
            and popped_o[0] == "load"
            and popped_o[1] == slot_addr
            and isinstance(popped_r, tuple)
            and popped_r
            and popped_r[0] == "load"
            and popped_r[1] == slot_addr
        ):
            ctx.save_stack.pop()
            orig.regs[family_o] = ("init", family_o)
            recomp.regs[family_r] = ("init", family_r)
            return True
    return False


def _invalidate_save_slots(ctx: Context, obs: list) -> None:
    """Any store that cannot be proven disjoint from a pending callee-save
    slot invalidates that record: the pop can no longer be trusted to
    restore the pushed value."""
    if not ctx.save_stack:
        return
    for entry in obs:
        if entry[0] != "store":
            continue
        address, size = entry[1], entry[2]
        if size == "stack":
            access: tuple = (address, 4, "push")
        else:
            access = (address, _WIDTHS.get(size), False)
        for record in ctx.save_stack:
            if record[3] and not _mem_disjoint((record[2], 4, "pop"), access):
                record[3] = False


def _slots_consistent(orig: SideState, recomp: SideState) -> bool:
    # pylint: disable=too-many-return-statements
    """Validate the frame-slot alpha-renaming: the two sides must map the
    same slot ids in the same order, and — when the layouts actually differ
    — every slot must be a self-contained region (known widths, no overlap
    between distinct slots, no escaped frame addresses)."""
    orig_disps = [
        d
        for d, slot in sorted(
            orig.slot_map.items(), key=lambda kv: (kv[1] is None, kv[1] or 0)
        )
        if slot is not None
    ]
    recomp_disps = [
        d
        for d, slot in sorted(
            recomp.slot_map.items(), key=lambda kv: (kv[1] is None, kv[1] or 0)
        )
        if slot is not None
    ]
    if len(orig_disps) != len(recomp_disps):
        return False
    if orig_disps == recomp_disps:
        # No renaming took place; nothing to prove.
        return True
    if orig.slots_escaped or recomp.slots_escaped:
        return False
    for state in (orig, recomp):
        widths: dict[int, set] = {}
        for disp, width in state.slot_accesses:
            if width is None:
                return False
            widths.setdefault(disp, set()).add(width)
        # Every renamed slot must be accessed with a single width: a byte
        # write followed by a dword read would pull the remaining bytes
        # from different (uninitialized) stack locations on each side.
        for accessed in widths.values():
            if len(accessed) != 1:
                return False
        spans = sorted((disp, next(iter(ws))) for disp, ws in widths.items())
        for (d1, w1), (d2, _) in zip(spans, spans[1:]):
            if d1 + w1 > d2:
                return False
    return True


def _uses_frame_slot_layout(orig: SideState, recomp: SideState) -> bool:
    orig_slots = sorted(d for d, slot in orig.slot_map.items() if slot is not None)
    recomp_slots = sorted(d for d, slot in recomp.slot_map.items() if slot is not None)
    return bool(orig_slots or recomp_slots) and orig_slots != recomp_slots


def _commutative_order_used(
    before_o: SideState,
    before_r: SideState,
    ctx: Context,
    ins_o: Instruction,
    ins_r: Instruction,
) -> bool:
    # pylint: disable=too-many-return-statements
    """Whether this paired operation needed commutative-order normalization."""
    if ins_o.mnemonic != ins_r.mnemonic:
        return False
    try:
        for operand_o, operand_r in zip(ins_o.operands, ins_r.operands):
            if operand_o[0] == operand_r[0] == "mem":
                terms_o = operand_o[3]
                terms_r = operand_r[3]
                if terms_o != terms_r and sorted(terms_o) == sorted(terms_r):
                    if mem_address(before_o, operand_o) == mem_address(
                        before_r, operand_r
                    ):
                        return True
        if ins_o.mnemonic in COMMUTATIVE_BINOPS and len(ins_o.operands) == 2:
            if len(ins_r.operands) != 2:
                return False
            a_o = read_operand(before_o, ctx, ins_o.operands[0])
            b_o = read_operand(before_o, ctx, ins_o.operands[1])
            a_r = read_operand(before_r, ctx, ins_r.operands[0])
            b_r = read_operand(before_r, ctx, ins_r.operands[1])
            if a_o == b_r and b_o == a_r and (a_o != a_r or b_o != b_r):
                return True
            if ins_o.mnemonic in ASSOCIATIVE_COMMUTATIVE_BINOPS:
                pair_o = _vsort(a_o, b_o)
                pair_r = _vsort(a_r, b_r)
                return pair_o != pair_r and _commutative_result(
                    ins_o.mnemonic, a_o, b_o
                ) == _commutative_result(ins_r.mnemonic, a_r, b_r)
            return False
        if ins_o.mnemonic in ("fadd", "fmul", "fiadd", "fimul"):
            if len(ins_o.operands) != 1 or len(ins_r.operands) != 1:
                return False
            a_o = before_o.x87.read(0)
            b_o = read_operand(before_o, ctx, ins_o.operands[0])
            a_r = before_r.x87.read(0)
            b_r = read_operand(before_r, ctx, ins_r.operands[0])
            return a_o == b_r and b_o == a_r and (a_o != a_r or b_o != b_r)
    except (Reject, IndexError, KeyError, ValueError, TypeError):
        return False
    return False


def verify_effective_match(
    orig_asm: list[str],
    recomp_asm: list[str],
    codes=None,
    metadata: FunctionMetadata | None = None,
    orig_meta: list[InstructionMeta | None] | None = None,
    recomp_meta: list[InstructionMeta | None] | None = None,
    recorder: AnalysisRecorder | None = None,
) -> bool:
    """True if the two instruction sequences can be proven equivalent
    modulo register allocation, frame-slot layout, commutative-operand
    order and inverted compare/jump conditions.

    `orig_meta` (optional, aligned with orig_asm) provides structured
    capstone facts; with them, an unmodeled register-only instruction can
    be stepped over precisely instead of requiring full synchronization."""
    # pylint: disable=too-many-branches,too-many-return-statements,too-many-statements
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    aligned = _aligned_indices(codes, len(orig_asm), len(recomp_asm))
    if aligned is None:
        if recorder is not None:
            recorder.mark_inconclusive("alignment_failure")
        return False

    orig = SideState()
    recomp = SideState()
    ctx = Context(metadata=metadata, recorder=recorder)
    last_index_o: int | None = None
    last_index_r: int | None = None

    try:
        for idx, (index_o, index_r) in enumerate(aligned):
            last_index_o, last_index_r = index_o, index_r
            line_o = orig_asm[index_o] if index_o is not None else None
            line_r = recomp_asm[index_r] if index_r is not None else None
            if line_o is None or line_r is None:
                side = recomp if line_o is None else orig
                line = line_r if line_o is None else line_o
                assert line is not None
                if not _one_sided_ok(side, ctx, idx, line):
                    if recorder is not None:
                        recorder.mark_inconclusive(
                            "alignment_failure", index_o, index_r
                        )
                    return False
                continue

            if DATA_LINE_RE.match(line_o) or DATA_LINE_RE.match(line_r):
                if line_o != line_r:
                    return False
                continue

            assert index_o is not None and index_r is not None
            try:
                ins_o = parse_instruction(line_o)
                ins_r = parse_instruction(line_r)
                _record_operand_candidate(ctx, index_o, index_r, ins_o, ins_r)
                obs_o: list = []
                obs_r: list = []
                ctx.bump_requested = False
                before_o = dict(orig.regs)
                before_r = dict(recomp.regs)
                state_before_o = _clone_state(orig)
                state_before_r = _clone_state(recomp)
                execute(orig, ctx, idx, ins_o, obs_o)
                execute(recomp, ctx, idx, ins_r, obs_r)
            except (Reject, IndexError, KeyError, ValueError, TypeError):
                # Unsupported or malformed instruction: only allowed if
                # both sides are textually identical, and then only when
                # its precise effects are known (capstone metadata) or the
                # two symbolic states are fully synchronized.
                if line_o != line_r:
                    if recorder is not None:
                        recorder.mark_inconclusive(
                            "unsupported_instruction", index_o, index_r
                        )
                    return False
                meta_o = (
                    orig_meta[index_o]
                    if orig_meta is not None and index_o is not None
                    else None
                )
                meta_r = (
                    recomp_meta[index_r]
                    if recomp_meta is not None and index_r is not None
                    else None
                )
                meta = meta_o or meta_r
                if meta is not None and _meta_step(orig, recomp, meta, idx):
                    _bump_linear_memory(ctx)
                    continue
                if not fully_synced(orig, recomp):
                    if recorder is not None:
                        recorder.mark_inconclusive(
                            "unsupported_instruction", index_o, index_r
                        )
                    return False
                resync((orig, recomp), idx, ctx)
                _bump_linear_memory(ctx)
                continue

            guard_state_size(orig, ctx)
            guard_state_size(recomp, ctx)

            if _callee_save_swap(ctx, ins_o, ins_r, obs_o, obs_r, orig, recomp):
                if ctx.bump_requested:
                    _bump_linear_memory(ctx)
                continue

            if obs_o != obs_r:
                meta_o = (
                    orig_meta[index_o]
                    if orig_meta is not None and index_o is not None
                    else None
                )
                meta_r = (
                    recomp_meta[index_r]
                    if recomp_meta is not None and index_r is not None
                    else None
                )
                _record_observable_difference(
                    ctx,
                    index_o,
                    index_r,
                    ins_o,
                    ins_r,
                    obs_o,
                    obs_r,
                    meta_o,
                    meta_r,
                )
                return False
            _invalidate_save_slots(ctx, obs_o)
            for entry in obs_o:
                ctx.add_matched(entry)

            # The same value written by both sides in this step (even to
            # different registers) is proven correspondence: remember it so
            # that dead leftovers of its computation are recognized at the
            # end of the run.
            written_o = [
                value
                for family, value in orig.regs.items()
                if value is not before_o[family]
            ]
            written_r = [
                value
                for family, value in recomp.regs.items()
                if value is not before_r[family]
            ]
            for value in written_o:
                if value in written_r:
                    ctx.add_matched(value)
            if any(
                family_o != family_r and value_o == value_r
                for family_o, value_o in orig.regs.items()
                if value_o is not before_o[family_o]
                for family_r, value_r in recomp.regs.items()
                if value_r is not before_r[family_r]
            ):
                ctx.categories.add("register_allocation")
            if _commutative_order_used(
                state_before_o, state_before_r, ctx, ins_o, ins_r
            ):
                ctx.categories.add("commutative_order")
            if (
                any(entry[0] == "branch" for entry in obs_o)
                and obs_o == obs_r
                and (
                    ins_o.mnemonic != ins_r.mnemonic
                    or state_before_o.flags != state_before_r.flags
                )
            ):
                ctx.categories.add("condition_inversion")

            # Linear execution is only valid while control stays linear:
            # whenever control may transfer (a branch), any divergence in
            # the current state escapes to the target, so it must already
            # be justified here — not by a later overwrite on the
            # fallthrough path.
            if any(entry[0] in CONTROL_TAGS for entry in obs_o):
                if not _divergences_justified(ctx, orig, recomp):
                    return False

            if ctx.bump_requested:
                _bump_linear_memory(ctx)

        # Values still diverged at the end must be dead. Callee-saved
        # registers and the stack pointer are externally observable machine
        # state and must match exactly; a divergent caller-saved register
        # is accepted only if both of its values were consumed by something
        # that was proven equal across the two sides.
        for family in FAMILIES:
            if orig.regs[family] == recomp.regs[family]:
                ctx.add_matched(orig.regs[family])
        for slot_o, slot_r in zip(orig.x87.known, recomp.x87.known):
            if slot_o == slot_r:
                ctx.add_matched(slot_o)

        dead_register_difference = False
        for family in FAMILIES:
            value_o, value_r = orig.regs[family], recomp.regs[family]
            if value_o == value_r:
                continue
            if family not in CALLER_SAVED:
                if recorder is not None:
                    summary_o, summary_r = _diagnostic_summaries(value_o, value_r)
                    recorder.record_difference(
                        "preserved_state",
                        last_index_o,
                        last_index_r,
                        {"register": family, "value": summary_o},
                        {"register": family, "value": summary_r},
                    )
                return False
            if _ins_split_ok(value_o, value_r, ctx):
                dead_register_difference = True
                continue
            for value in (value_o, value_r):
                if _is_scratch(value):
                    dead_register_difference = True
                    continue
                if not _contained(value, ctx):
                    if recorder is not None:
                        recorder.mark_inconclusive("analysis_limit")
                    return False
                dead_register_difference = True
        if dead_register_difference and "register_allocation" not in ctx.categories:
            ctx.categories.add("dead_operation")

        # Every callee-save substitution must have been balanced by its pop,
        # and any frame-slot renaming must describe a consistent layout.
        if ctx.save_stack:
            if recorder is not None:
                recorder.mark_inconclusive("analysis_limit")
            return False
        if not _slots_consistent(orig, recomp):
            if recorder is not None:
                recorder.mark_inconclusive("analysis_limit")
            return False
        if _uses_frame_slot_layout(orig, recomp):
            ctx.categories.add("frame_slot_layout")

        if orig.x87.state_key()[1:] != recomp.x87.state_key()[1:]:
            return False
        if len(orig.x87.known) != len(recomp.x87.known):
            return False
        for slot_o, slot_r in zip(orig.x87.known, recomp.x87.known):
            if slot_o != slot_r:
                if not (_contained(slot_o, ctx) and _contained(slot_r, ctx)):
                    return False
    except (Reject, RecursionError):
        if recorder is not None:
            recorder.mark_inconclusive("analysis_limit")
        return False

    if recorder is not None:
        recorder.reasons.update(ctx.categories)
    return True


# ---------------------------------------------------------------------------
# Per-line effect summaries for dependency-aware instruction relocation


@dataclass(frozen=True)
class LineEffects:
    """Conservative summary of one instruction's reads and writes, used to
    decide whether two instructions may be reordered. Memory accesses are
    (address value, width, is_stack_slot) with addresses resolved by
    symbolic execution (see sequence_effects), so e.g. `[esi]` after
    `lea esi, [ebx + 0x1c6]` is comparable with `[ebx + 0xb0]`."""

    # pylint: disable=too-many-instance-attributes

    regs_read: frozenset = frozenset()
    regs_written: frozenset = frozenset()
    reads_flags: bool = False
    writes_flags: bool = False
    mem_reads: tuple = ()
    mem_writes: tuple = ()
    x87: bool = False
    barrier: bool = False


BARRIER = LineEffects(barrier=True)

_RMW_BINOPS = frozenset(
    {"add", "sub", "and", "or", "xor", "shl", "shr", "sar", "rol", "ror", "adc", "sbb"}
)
_X87_MEM_WRITERS = frozenset({"fst", "fstp", "fist", "fistp", "fnstcw", "fbstp"})


@cache
def _line_base_effects(line: str) -> LineEffects:
    """Textual effect summary for one sanitized instruction: register
    families, flags, x87 use and barriers. Memory accesses are filled in
    by sequence_effects. Anything not modeled (calls, jumps, string ops,
    unparsable text) is a scheduling barrier."""
    # pylint: disable=too-many-branches,too-many-statements,too-many-return-statements
    if DATA_LINE_RE.match(line):
        return BARRIER
    try:
        ins = parse_instruction(line)
    except (Reject, IndexError, KeyError, ValueError):
        return BARRIER
    if ins.prefix:
        return BARRIER

    mnemonic = ins.mnemonic
    ops = ins.operands

    regs_read: set = set()
    regs_written: set = set()
    x87 = mnemonic.startswith("f")
    reads_flags = False
    writes_flags = False

    def use(op, write: bool = False) -> None:
        kind = op[0]
        if kind == "reg":
            (regs_written if write else regs_read).add(REGISTERS[op[1]][0])
        elif kind == "mem":
            for reg, _ in op[3]:
                regs_read.add(REGISTERS[reg][0])
        elif kind not in ("imm", "sym", "st"):
            raise Reject

    try:
        if mnemonic in ("mov", "movsx", "movzx") and len(ops) == 2:
            use(ops[1])
            use(ops[0], write=True)
        elif mnemonic == "lea" and len(ops) == 2 and ops[1][0] == "mem":
            for reg, _ in ops[1][3]:
                regs_read.add(REGISTERS[reg][0])
            use(ops[0], write=True)
        elif mnemonic in _RMW_BINOPS and len(ops) == 2:
            use(ops[0])
            use(ops[0], write=True)
            use(ops[1])
            writes_flags = True
            reads_flags = mnemonic in ("adc", "sbb")
        elif mnemonic == "imul" and len(ops) == 3:
            use(ops[0], write=True)
            use(ops[1])
            use(ops[2])
            writes_flags = True
        elif mnemonic == "imul" and len(ops) == 2:
            use(ops[0])
            use(ops[0], write=True)
            use(ops[1])
            writes_flags = True
        elif mnemonic in ("inc", "dec", "neg", "not") and len(ops) == 1:
            use(ops[0])
            use(ops[0], write=True)
            writes_flags = mnemonic != "not"
        elif mnemonic in ("cmp", "test") and len(ops) == 2:
            use(ops[0])
            use(ops[1])
            writes_flags = True
        elif mnemonic in ("mul", "imul", "div", "idiv") and len(ops) == 1:
            use(ops[0])
            regs_read.update(("a", "d"))
            regs_written.update(("a", "d"))
            writes_flags = True
        elif mnemonic == "cdq":
            regs_read.add("a")
            regs_written.add("d")
        elif mnemonic == "cwde":
            regs_read.add("a")
            regs_written.add("a")
        elif mnemonic == "sahf":
            regs_read.add("a")
            writes_flags = True
        elif mnemonic == "lahf":
            regs_written.add("a")
            reads_flags = True
        elif mnemonic == "push" and len(ops) == 1:
            use(ops[0])
            regs_read.add("sp")
            regs_written.add("sp")
        elif mnemonic == "pop" and len(ops) == 1:
            use(ops[0], write=True)
            regs_read.add("sp")
            regs_written.add("sp")
        elif mnemonic.startswith("set") and mnemonic[3:] in CC_CANON and len(ops) == 1:
            use(ops[0], write=True)
            reads_flags = True
        elif mnemonic in ("nop", "int3"):
            pass
        elif mnemonic in JCC_MNEMONICS or mnemonic in ("loop", "loope", "loopne"):
            return LineEffects(reads_flags=True, barrier=True)
        elif mnemonic in ("call", "ret"):
            # Calls clobber the flags; at ret they are dead.
            return LineEffects(writes_flags=True, barrier=True)
        elif x87:
            for op in ops:
                if op[0] == "mem":
                    use(op, write=mnemonic in _X87_MEM_WRITERS)
            if mnemonic == "fnstsw":
                regs_written.add("a")
        else:
            return BARRIER
    except (Reject, IndexError, KeyError):
        return BARRIER

    return LineEffects(
        regs_read=frozenset(regs_read),
        regs_written=frozenset(regs_written),
        reads_flags=reads_flags,
        writes_flags=writes_flags,
        x87=x87,
        barrier=False,
    )


def _havoc(state: SideState, idx: int) -> None:
    """Discard everything we know about the state after an instruction
    outside the model."""
    for family in FAMILIES:
        state.regs[family] = ("havoc", idx, family)
    state.flags = ("havoc_flags", idx)
    state.carry = ("havoc_cf", idx)
    state.fpu_flags = ("havoc_fpuflags", idx)
    state.x87 = X87Stack(epoch=-idx - 1)


def sequence_effects(asm: list[str]) -> list[LineEffects] | None:
    """Symbolically execute one instruction sequence and return a per-line
    effect summary with memory addresses resolved to symbolic values.
    Returns None if the sequence cannot be analyzed at all."""
    state = SideState(rename_slots=False)
    ctx = Context()
    result = []
    try:
        for idx, line in enumerate(asm):
            base = _line_base_effects(line)
            ctx.trace = []
            failed = False
            try:
                ins = parse_instruction(line)
                execute(state, ctx, idx, ins, [])
                guard_state_size(state, ctx)
            except (Reject, IndexError, KeyError, ValueError, TypeError):
                _havoc(state, idx)
                failed = True
            if base.barrier or failed:
                # Keep the flag information of modeled barriers (a jcc reads
                # the flags, a call clobbers them).
                result.append(BARRIER if failed and not base.barrier else base)
                continue
            trace = ctx.trace
            result.append(
                LineEffects(
                    regs_read=base.regs_read,
                    regs_written=base.regs_written,
                    reads_flags=base.reads_flags,
                    writes_flags=base.writes_flags,
                    mem_reads=tuple(
                        (addr, width, stack)
                        for op, addr, width, stack in trace
                        if op == "r"
                    ),
                    mem_writes=tuple(
                        (addr, width, stack)
                        for op, addr, width, stack in trace
                        if op == "w"
                    ),
                    x87=base.x87,
                    barrier=False,
                )
            )
    except (Reject, RecursionError):
        return None
    return result


def _flatten_mem(addr: Value) -> Value:
    """Fold scale-1 base registers that hold a computed address (from lea)
    into the memory expression itself, so `[esi]` with esi = &[ebx + 0x1c6]
    compares as `[ebx + 0x1c6]`."""
    _, seg, terms, disp, syms = addr
    for _ in range(8):
        folded = None
        for term in terms:
            value, scale = term
            if (
                scale == 1
                and isinstance(value, tuple)
                and len(value) == 2
                and value[0] == "addr"
                and value[1][1] in ("", seg)
            ):
                folded = term
                break
        if folded is None:
            break
        inner = folded[0][1]
        terms = tuple(t for t in terms if t is not folded) + inner[2]
        disp += inner[3]
        syms = tuple(sorted(set(syms) | set(inner[4])))
        seg = seg or inner[1]
    return ("mem", seg, tuple(sorted(terms, key=repr)), disp, syms)


def _stack_rooted(value: Value) -> bool:
    """Is the value derived from the stack pointer or frame pointer?"""
    if not isinstance(value, tuple) or not value:
        return False
    if value in (("init", "sp"), ("init", "bp")):
        return True
    if value[0] == "spadd":
        return _stack_rooted(value[1])
    if value[0] == "addr":
        return any(_stack_rooted(v) for v, _ in value[1][2])
    if value[0] == "ins_r16":
        return _stack_rooted(value[1]) or _stack_rooted(value[2])
    return False


def _is_pure_global(mem: Value) -> bool:
    return not mem[2] and bool(mem[4])


def _unwind_spadd(value: Value, offset: int = 0) -> tuple[Value, int]:
    while isinstance(value, tuple) and value and value[0] == "spadd":
        offset += value[2]
        value = value[1]
    return (value, offset)


def _abs_stack_offset(addr: Value, is_slot) -> tuple[Value, int] | None:
    """Resolve an access to (root value, byte offset) when its address is a
    plain chain of constant adjustments over one root — a push/pop slot, or
    a single-register memory operand like [ebp - 8] or [esp + 4]."""
    if is_slot:
        return _unwind_spadd(addr)
    mem = _flatten_mem(addr)
    if len(mem[2]) == 1 and not mem[4]:
        value, scale = mem[2][0]
        if scale == 1:
            root, offset = _unwind_spadd(value)
            return (root, offset + mem[3])
    return None


def _ranges_disjoint(a_disp: int, a_width, b_disp: int, b_width) -> bool:
    if a_width is None or b_width is None:
        return False
    return a_disp + a_width <= b_disp or b_disp + b_width <= a_disp


def _mem_disjoint(a: tuple, b: tuple) -> bool:
    """Can the two memory accesses be proven non-overlapping?
    Accesses are (address value, width, stack_kind) where stack_kind is
    False for ordinary operands, "push" for a fresh slot below the stack
    pointer, "pop" for a read of the top of the stack."""
    # pylint: disable=too-many-return-statements
    a_addr, a_width, a_stack = a
    b_addr, b_width, b_stack = b

    if a_stack or b_stack:
        a_res = _abs_stack_offset(a_addr, a_stack)
        b_res = _abs_stack_offset(b_addr, b_stack)
        if (
            a_res is not None
            and b_res is not None
            and a_res[0] == b_res[0]
            and _ranges_disjoint(a_res[1], a_width, b_res[1], b_width)
        ):
            return True
        if a_stack and b_stack:
            return False
        other = _flatten_mem(b_addr if a_stack else a_addr)
        # A stack slot never overlaps a named global. An access through an
        # unknown pointer, however, must be assumed to alias the stack:
        # nothing proves an incoming pointer cannot equal the slot address.
        return _is_pure_global(other)

    a_mem = _flatten_mem(a_addr)
    b_mem = _flatten_mem(b_addr)

    if a_mem[1] != b_mem[1]:
        # Different segment prefixes: assume they can alias.
        return False

    # Same base values (symbolically identical registers/symbols): the two
    # accesses differ only by constant displacement.
    if a_mem[2] == b_mem[2] and a_mem[4] == b_mem[4]:
        return _ranges_disjoint(a_mem[3], a_width, b_mem[3], b_width)

    global_a = _is_pure_global(a_mem)
    global_b = _is_pure_global(b_mem)

    if global_a and global_b and a_mem[4] != b_mem[4]:
        # Two different named globals do not overlap.
        return True

    # Stack/frame memory never overlaps a named global.
    stack_a = any(_stack_rooted(v) for v, _ in a_mem[2])
    stack_b = any(_stack_rooted(v) for v, _ in b_mem[2])
    if (global_a and stack_b) or (global_b and stack_a):
        return True

    return False


def effects_conflict(moved: LineEffects, other: LineEffects) -> bool:
    """True if the moved instruction cannot be reordered across `other`."""
    # pylint: disable=too-many-return-statements
    if moved.barrier or other.barrier:
        return True
    if moved.regs_written & (other.regs_read | other.regs_written):
        return True
    if moved.regs_read & other.regs_written:
        return True
    if moved.writes_flags and other.reads_flags:
        return True
    if moved.reads_flags and other.writes_flags:
        return True
    # x87 instructions depend on the fp stack order.
    if moved.x87 and other.x87:
        return True
    for access in moved.mem_writes:
        for against in other.mem_reads + other.mem_writes:
            if not _mem_disjoint(access, against):
                return True
    for access in moved.mem_reads:
        for against in other.mem_writes:
            if not _mem_disjoint(access, against):
                return True
    return False


def flags_dead_at(effects_list: list[LineEffects], start: int) -> bool:
    """Are the CPU flags provably dead (rewritten before being read) from
    line `start` onward?"""
    for effects in effects_list[start:]:
        if effects.reads_flags:
            return False
        if effects.writes_flags:
            return True
        if effects.barrier:
            # Unknown control flow: assume the flags could be read.
            return False
    return True


# ---------------------------------------------------------------------------
# CFG-aware verification


def _clone_state(state: SideState) -> SideState:
    clone = SideState(rename_slots=state.rename_slots)
    clone.regs = dict(state.regs)
    clone.flags = state.flags
    clone.carry = state.carry
    clone.fpu_flags = state.fpu_flags
    clone.x87 = X87Stack(
        known=list(state.x87.known),
        deep_pops=state.x87.deep_pops,
        epoch=state.x87.epoch,
    )
    clone.slot_map = dict(state.slot_map)
    clone.slot_accesses = list(state.slot_accesses)
    clone.slots_escaped = state.slots_escaped
    return clone


@dataclass
class _CfgState:
    """Paired machine state at a basic-block boundary.

    Memory is one relational value rather than one value per side: every
    store and call is already an observable that must match, so equal input
    memories remain equal.  Carrying the value through the CFG is important;
    a process-global generation would let visiting one path change loads on
    another path and is neither a concrete execution nor a sound join.
    """

    orig: SideState
    recomp: SideState
    memory: int | Value


def _clone_cfg_state(state: _CfgState) -> _CfgState:
    return _CfgState(_clone_state(state.orig), _clone_state(state.recomp), state.memory)


def _join_pairwise(
    existing: tuple[Value, Value], incoming: tuple[Value, Value], key: tuple
) -> tuple[Value, Value]:
    """Three-level lattice: exact pair -> paired phi (cross-equal,
    unknown value) -> per-side poison (nothing provable; any observable
    use will mismatch). Monotone, so the fixpoint terminates."""
    if existing == incoming:
        return existing
    phi = (("phi", *key), ("phi", *key))
    if existing == phi and incoming[0] == incoming[1]:
        return phi
    if (
        existing[0] == existing[1]
        and incoming[0] == incoming[1]
        and existing != (("poison", *key, "o"), ("poison", *key, "r"))
    ):
        return phi
    return (("poison", *key, "o"), ("poison", *key, "r"))


def _join_states(
    entry: _CfgState,
    incoming: _CfgState,
    block: int,
) -> _CfgState | None:
    # pylint: disable=too-many-return-statements
    """Merge an incoming state pair into a block's entry pair. Returns the
    (possibly new) entry pair, or None if the states cannot be merged
    (differing x87 shapes)."""
    entry_o, entry_r = entry.orig, entry.recomp
    in_o, in_r = incoming.orig, incoming.recomp
    if len(entry_o.x87.known) != len(entry_r.x87.known):
        return None
    if len(in_o.x87.known) != len(in_r.x87.known):
        return None
    if len(entry_o.x87.known) != len(in_o.x87.known):
        return None
    if entry_o.x87.deep_pops != entry_r.x87.deep_pops:
        return None
    if in_o.x87.deep_pops != in_r.x87.deep_pops:
        return None
    if entry_o.x87.deep_pops != in_o.x87.deep_pops:
        return None
    out_o = _clone_state(entry_o)
    out_r = _clone_state(entry_r)
    for family in FAMILIES:
        joined = _join_pairwise(
            (entry_o.regs[family], entry_r.regs[family]),
            (in_o.regs[family], in_r.regs[family]),
            (block, family),
        )
        out_o.regs[family], out_r.regs[family] = joined
    for attr in ("flags", "carry", "fpu_flags"):
        joined = _join_pairwise(
            (getattr(entry_o, attr), getattr(entry_r, attr)),
            (getattr(in_o, attr), getattr(in_r, attr)),
            (block, attr),
        )
        setattr(out_o, attr, joined[0])
        setattr(out_r, attr, joined[1])
    slots = zip(
        entry_o.x87.known,
        entry_r.x87.known,
        in_o.x87.known,
        in_r.x87.known,
    )
    for index, (entry_slot_o, entry_slot_r, in_slot_o, in_slot_r) in enumerate(slots):
        joined = _join_pairwise(
            (entry_slot_o, entry_slot_r),
            (in_slot_o, in_slot_r),
            (block, "st", index),
        )
        out_o.x87.known[index], out_r.x87.known[index] = joined
    if entry_o.x87.epoch != entry_r.x87.epoch:
        return None
    if in_o.x87.epoch != in_r.x87.epoch:
        return None
    if entry_o.x87.epoch != in_o.x87.epoch:
        return None

    if entry.memory == incoming.memory:
        memory = entry.memory
    else:
        memory = ("cfg_mem_phi", block)
    return _CfgState(out_o, out_r, memory)


def _states_equal(a: _CfgState, b: _CfgState) -> bool:
    return a.memory == b.memory and all(
        x.regs == y.regs
        and x.flags == y.flags
        and x.carry == y.carry
        and x.fpu_flags == y.fpu_flags
        and x.x87.state_key() == y.x87.state_key()
        for x, y in ((a.orig, b.orig), (a.recomp, b.recomp))
    )


def _converged(orig: SideState, recomp: SideState) -> bool:
    return (
        orig.regs == recomp.regs
        and orig.flags == recomp.flags
        and orig.carry == recomp.carry
        and orig.fpu_flags == recomp.fpu_flags
        and orig.x87.state_key() == recomp.x87.state_key()
    )


def _same_meta_effects(
    orig: InstructionMeta | None, recomp: InstructionMeta | None
) -> bool:
    """Whether two metadata records describe the same non-address effects.

    The textual instruction is already identical when this is used.  Still,
    consume metadata only as a pair: trusting facts collected from one binary
    to model the other would defeat the purpose of structured input.
    """
    if orig is None or recomp is None:
        return False
    fields = (
        "mnemonic",
        "regs_read",
        "regs_written",
        "reads_flags",
        "writes_flags",
        "accesses_memory",
        "is_jump",
        "is_call",
        "is_ret",
    )
    return all(getattr(orig, field) == getattr(recomp, field) for field in fields)


def verify_cfg_effective_match(
    orig_asm: list[str],
    recomp_asm: list[str],
    orig_targets: list[int | None],
    recomp_targets: list[int | None],
    metadata: FunctionMetadata | None = None,
    orig_meta: list[InstructionMeta | None] | None = None,
    recomp_meta: list[InstructionMeta | None] | None = None,
    recorder: AnalysisRecorder | None = None,
) -> bool:
    """CFG-aware verification: split both sequences into basic blocks
    (which must be structurally identical under the line pairing), then
    verify every block with state pairs flowing along the edges — forked
    at conditional branches and joined at merge points. This proves pairs
    that linear verification cannot (a divergence that is live across a
    branch and consumed after the join) and rejects pairs it must
    (a divergence created in one arm and overwritten after the join)."""
    # pylint: disable=too-many-branches,too-many-statements,too-many-return-statements
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    total = len(orig_asm)
    if (
        len(recomp_asm) != total
        or len(orig_targets) != total
        or len(recomp_targets) != total
        or total == 0
    ):
        if recorder is not None:
            recorder.mark_inconclusive("alignment_failure")
        return False
    if orig_targets != recomp_targets:
        if recorder is not None:
            differing = next(
                (
                    index
                    for index, pair in enumerate(zip(orig_targets, recomp_targets))
                    if pair[0] != pair[1]
                ),
                None,
            )
            if differing is not None:
                meta_o = orig_meta[differing] if orig_meta is not None else None
                meta_r = recomp_meta[differing] if recomp_meta is not None else None
                recorder.record_difference(
                    "branch_target",
                    differing,
                    differing,
                    _target_facts(
                        parse_instruction(orig_asm[differing]),
                        meta_o,
                        orig_targets[differing],
                    ),
                    _target_facts(
                        parse_instruction(recomp_asm[differing]),
                        meta_r,
                        recomp_targets[differing],
                    ),
                )
        return False

    def classify(asm: list[str]) -> list[str]:
        kinds = []
        for line in asm:
            mnemonic = line.partition(" ")[0]
            if mnemonic in JCC_MNEMONICS:
                kinds.append("jcc")
            elif mnemonic in ("jmp", "ret"):
                kinds.append(mnemonic)
            elif mnemonic in ("loop", "loope", "loopne", "jcxz", "jecxz"):
                kinds.append("jcc")
            elif DATA_LINE_RE.match(line):
                kinds.append("data")
            else:
                kinds.append("code")
        return kinds

    kinds = classify(orig_asm)
    if kinds != classify(recomp_asm):
        if recorder is not None:
            recorder.mark_inconclusive("unsupported_control_flow")
        return False
    leaders = {0}
    for i in range(total):
        target = orig_targets[i]
        if target is not None:
            if not 0 <= target < total:
                if recorder is not None:
                    recorder.mark_inconclusive("unsupported_control_flow")
                return False
            if kinds[target] == "data":
                # A control-flow edge into bytes classified as a table is an
                # inconsistent disassembly, not a block this verifier can run.
                if recorder is not None:
                    recorder.mark_inconclusive("unsupported_control_flow")
                return False
            leaders.add(target)
        if kinds[i] in ("jcc", "jmp", "ret", "data") and i + 1 < total:
            leaders.add(i + 1)
    order = sorted(leaders)
    starts = {start: n for n, start in enumerate(order)}
    ends = [order[n + 1] if n + 1 < len(order) else total for n in range(len(order))]

    def successors(block: int) -> list[int]:
        last = ends[block] - 1
        kind = kinds[last]
        if kind in ("ret", "data"):
            return []
        if kind == "jmp":
            target = orig_targets[last]
            return [starts[target]] if target is not None else []
        if kind == "jcc":
            result = []
            target = orig_targets[last]
            if target is not None:
                result.append(starts[target])
            if ends[block] < total:
                result.append(starts[ends[block]])
            return result
        return [starts[ends[block]]] if ends[block] < total else []

    entry: dict[int, _CfgState] = {
        0: _CfgState(
            SideState(rename_slots=False),
            SideState(rename_slots=False),
            ("cfg_mem_init",),
        )
    }
    pending = [0]
    visits = 0

    def run_block(block: int) -> bool:
        flow = _clone_cfg_state(entry[block])
        orig_state, recomp_state = flow.orig, flow.recomp
        ctx = Context(gen=flow.memory, metadata=metadata, recorder=recorder)
        for i in range(order[block], ends[block]):
            line_o, line_r = orig_asm[i], recomp_asm[i]
            if kinds[i] == "data":
                if line_o != line_r:
                    return False
                continue
            try:
                ins_o = parse_instruction(line_o)
                ins_r = parse_instruction(line_r)
                _record_operand_candidate(ctx, i, i, ins_o, ins_r)
                obs_o: list = []
                obs_r: list = []
                ctx.bump_requested = False
                before_o = dict(orig_state.regs)
                before_r = dict(recomp_state.regs)
                state_before_o = _clone_state(orig_state)
                state_before_r = _clone_state(recomp_state)
                execute(orig_state, ctx, i, ins_o, obs_o)
                execute(recomp_state, ctx, i, ins_r, obs_r)
            except (Reject, IndexError, KeyError, ValueError, TypeError):
                if line_o != line_r:
                    if recorder is not None:
                        recorder.mark_inconclusive("unsupported_instruction", i, i)
                    return False
                meta_o = orig_meta[i] if orig_meta is not None else None
                meta_r = recomp_meta[i] if recomp_meta is not None else None
                if _same_meta_effects(meta_o, meta_r) and _meta_step(
                    orig_state, recomp_state, meta_o, i
                ):
                    ctx.gen = ("cfg_mem_meta", i)
                    continue
                if not fully_synced(orig_state, recomp_state):
                    if recorder is not None:
                        recorder.mark_inconclusive("unsupported_instruction", i, i)
                    return False
                resync((orig_state, recomp_state), i, ctx)
                ctx.gen = ("cfg_mem_resync", i)
                continue

            guard_state_size(orig_state, ctx)
            guard_state_size(recomp_state, ctx)

            # Canonicalize internal branch targets to block ids: with the
            # structural check done, differing displacement text (from
            # different instruction encodings) is irrelevant.
            target = orig_targets[i]
            if target is not None:
                for entries in (obs_o, obs_r):
                    for k, obs_entry in enumerate(entries):
                        if obs_entry[0] in CONTROL_TAGS - {"jmpind"}:
                            entries[k] = (*obs_entry[:-1], ("L", starts[target]))

            if obs_o != obs_r:
                meta_o = orig_meta[i] if orig_meta is not None else None
                meta_r = recomp_meta[i] if recomp_meta is not None else None
                _record_observable_difference(
                    ctx,
                    i,
                    i,
                    ins_o,
                    ins_r,
                    obs_o,
                    obs_r,
                    meta_o,
                    meta_r,
                )
                return False
            _invalidate_save_slots(ctx, obs_o)
            for obs_entry in obs_o:
                ctx.add_matched(obs_entry)
            if any(
                family_o != family_r and value_o == value_r
                for family_o, value_o in orig_state.regs.items()
                if value_o is not before_o[family_o]
                for family_r, value_r in recomp_state.regs.items()
                if value_r is not before_r[family_r]
            ):
                ctx.categories.add("register_allocation")
            if _commutative_order_used(
                state_before_o, state_before_r, ctx, ins_o, ins_r
            ):
                ctx.categories.add("commutative_order")
            if (
                any(entry[0] == "branch" for entry in obs_o)
                and obs_o == obs_r
                and (
                    ins_o.mnemonic != ins_r.mnemonic
                    or state_before_o.flags != state_before_r.flags
                )
            ):
                ctx.categories.add("condition_inversion")
            # We do not yet pair jump-table destinations. A computed jump
            # therefore cannot be justified by this CFG proof. The lockstep
            # verifier still handles identical/converged cases before this
            # path is attempted.
            if any(obs_entry[0] == "jmpind" for obs_entry in obs_o):
                if recorder is not None:
                    recorder.mark_inconclusive("unsupported_control_flow")
                return False

            # A direct edge outside the excerpt exposes the complete machine
            # state to code this proof does not inspect. Be conservative for
            # both unconditional exits and the taken edge of a conditional.
            if kinds[i] in ("jmp", "jcc") and target is None:
                if not _converged(orig_state, recomp_state):
                    if recorder is not None:
                        recorder.mark_inconclusive("unsupported_control_flow")
                    return False
            if ctx.bump_requested:
                ctx.gen = ("cfg_mem_write", i)

        last_kind = kinds[ends[block] - 1]
        if (
            last_kind == "ret"
            and orig_state.x87.state_key() != recomp_state.x87.state_key()
        ):
            return False
        if last_kind == "code" and ends[block] == total:
            # Falling out of the disassembled function is not a modeled exit.
            return False

        outgoing = _CfgState(orig_state, recomp_state, ctx.gen)
        if recorder is not None:
            recorder.reasons.update(ctx.categories)
        # Propagate to successors.
        for successor in successors(block):
            if successor not in entry:
                entry[successor] = _clone_cfg_state(outgoing)
                pending.append(successor)
            else:
                joined = _join_states(entry[successor], outgoing, successor)
                if joined is None:
                    if recorder is not None:
                        recorder.mark_inconclusive("unsupported_control_flow")
                    return False
                if not _states_equal(joined, entry[successor]):
                    entry[successor] = joined
                    pending.append(successor)
        return True

    try:
        while pending:
            block = pending.pop()
            visits += 1
            if visits > 8 * len(order) + 64:
                if recorder is not None:
                    recorder.mark_inconclusive("analysis_limit")
                return False
            if not run_block(block):
                return False
    except (Reject, RecursionError):
        if recorder is not None:
            recorder.mark_inconclusive("analysis_limit")
        return False
    return True
