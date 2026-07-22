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

# Canonical flag state of every zero idiom (`xor r, r`, `sub r, r`,
# `cmp r, r`): the result is zero, CF and OF are cleared.
ZERO_FLAGS = ("cmp", ("imm", 0), ("imm", 0))

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
    # Every ordinary memory read performed by this side, as (address value,
    # memory generation). Used to discharge the trap-parity obligation of a
    # one-sided load on the other side: an extra explicit load is only
    # harmless when the other side provably reads the same address at the
    # same memory generation (e.g. folded into another instruction).
    load_log: set = field(default_factory=set)
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
    # Memory summary tag, shared by both sides: the tag of the most recent
    # store/clobber event, or the scope's initial value. Used as a block's
    # outgoing memory state and as the base tag for loads that no recorded
    # store can alias.
    gen: int | Value = 0
    # Committed memory events, newest last: (tag, access) for a store with
    # a known (address value, width, stack kind), or (tag, None) for a
    # clobber-all (call, string write, resync). A load is tagged by the
    # newest event that may alias it, so independent loads keep their tag
    # across unrelated stores.
    mem_events: list[tuple] = field(default_factory=list)
    # Whether a pointer into this function's own frame may have escaped
    # (stored to memory or passed to a callee). Until then, memory below
    # the entry stack pointer is private scratch that no incoming pointer
    # can alias.
    stack_escaped: bool = False
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
    # Trap-parity obligations from one-sided memory reads: (other side's
    # state, address value, memory generation). Discharged at the end of
    # the verification scope against the other side's load_log.
    load_obligations: list[tuple] = field(default_factory=list)
    # Live one-sided spills: [side state, entry-sp offset, value, event
    # tag]. Must be empty at every call: a pushed value still live at a
    # call would be an argument the other side never passed.
    scratch_pushes: list[list] = field(default_factory=list)
    # Which acceptance features fired, for debug/audit logging.
    categories: set[str] = field(default_factory=set)
    # PDB-derived return-type and callee-convention facts, if available.
    metadata: FunctionMetadata | None = None
    # Structured evidence sink for the current verifier strategy.
    recorder: AnalysisRecorder | None = None

    def __post_init__(self) -> None:
        # The memory tag of the scope's entry state: loads that precede
        # every recorded store (or that no recorded store aliases) carry it.
        self.initial_gen = self.gen

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


# A load only needs the newest may-aliasing store. Scanning the whole event
# log per load would be quadratic on huge straight-line functions; past the
# cap, the newest unresolved tag is a sound (merely coarser) answer.
_ALIAS_SCAN_LIMIT = 128


def _load_tag(ctx: Context, address: Value, width, stack) -> int | Value:
    """Tag identifying which memory state a load reads: the tag of the
    newest committed store that may alias it (or of any clobber), else the
    scope's initial memory tag. Two loads of the same address with the same
    tag are the same read."""
    access = (address, width, stack)
    events = ctx.mem_events
    scanned = 0
    for index in range(len(events) - 1, -1, -1):
        tag, store = events[index]
        scanned += 1
        if scanned > _ALIAS_SCAN_LIMIT:
            return tag
        if store is None or _store_may_alias_load(store, access, ctx.stack_escaped):
            return tag
    return ctx.initial_gen


def _frame_pointer_value(value: Value) -> bool:
    """Does this value hold a pointer into the current function's own
    frame (strictly below the entry stack pointer)? Such a value reaching
    memory or a callee makes the frame externally reachable."""
    if not isinstance(value, tuple) or not value:
        return False
    if value[0] == "addr":
        resolved = _abs_stack_offset(value[1], False)
        if resolved is None:
            # An escaping address we cannot resolve: assume the worst
            # when it is stack-rooted at all.
            return any(_stack_rooted(term) for term, _ in value[1][2])
        root, offset = resolved
        return root == ("init", "sp") and offset < 0
    if value[0] == "spadd":
        root, offset = _unwind_spadd(value)
        return root == ("init", "sp") and offset < 0
    return False


def _store_may_alias_load(store: tuple, load: tuple, stack_escaped: bool) -> bool:
    """May this committed store affect this load? Refines _mem_disjoint
    with an ABI fact: while no frame pointer has escaped, memory strictly
    below the entry stack pointer is the function's private scratch, which
    no incoming (unknown) pointer can alias."""
    if _mem_disjoint(store, load):
        return False
    if not stack_escaped:
        for scratch, other in ((store, load), (load, store)):
            resolved = _abs_stack_offset(scratch[0], scratch[2])
            if (
                resolved is not None
                and resolved[0] == ("init", "sp")
                and resolved[1] < 0
                and not other[2]
            ):
                other_mem = _flatten_mem(other[0])
                if not any(_stack_rooted(term) for term, _ in other_mem[2]):
                    return False
    return True


def _commit_clobber(ctx: Context, marker) -> None:
    """Record a write to unknown locations: every later load re-reads."""
    tag = ("mem", marker, "clobber")
    ctx.mem_events.append((tag, None))
    ctx.gen = tag


def _commit_memory(ctx: Context, obs: list, marker) -> None:
    """Commit the memory effects of one verified instruction pair. Deferred
    until after both sides executed so that loads within the pair observe
    the same pre-instruction memory."""
    for k, entry in enumerate(obs):
        kind = entry[0]
        if kind == "store":
            _, address, size, value = entry
            width = 4 if size == "stack" else _WIDTHS.get(size)
            stack = "push" if size == "stack" else False
            tag = ("mem", marker, k)
            ctx.mem_events.append((tag, (address, width, stack)))
            ctx.gen = tag
            if _frame_pointer_value(value):
                ctx.stack_escaped = True
        elif kind == "call":
            if ctx.scratch_pushes:
                # A one-sided spill still on the stack at a call would be
                # an extra argument: not provably equivalent.
                raise Reject
            for argument in entry[2:]:
                if _frame_pointer_value(argument):
                    ctx.stack_escaped = True
            _commit_clobber(ctx, (marker, k))
        elif isinstance(kind, tuple):
            # String instruction: (mnemonic, prefix). Writers clobber; the
            # data they copy was already committed by its original store.
            if STRING_OPS.get(kind[0], ("", "", False))[2]:
                _commit_clobber(ctx, (marker, k))


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
    pairs = [(state.read_reg(reg), scale) for reg, scale in reg_terms]
    if isinstance(disp_key, int):
        # Fold constant stack-pointer adjustments into the displacement so
        # that e.g. [esp + 8] before a push and [esp + 0xc] after it denote
        # the same address. Skipped for alpha-renamed frame slots, whose
        # key is the slot id rather than an offset.
        folded = []
        for value, scale in pairs:
            base, offset = _unwind_spadd(value)
            if offset:
                disp_key += scale * offset
                value = base
            folded.append((value, scale))
        pairs = folded
    terms = tuple(sorted(pairs, key=repr))
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
        width = _WIDTHS.get(op[1])
        if ctx.trace is not None:
            ctx.trace.append(("r", address, width, False))
        tag = _load_tag(ctx, address, width, False)
        state.load_log.add((address, tag))
        return ("load", address, op[1], tag)
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
        elif mnemonic in ("and", "or") and a == b:
            # and/or of a value with itself leaves it unchanged.
            value = a
        else:
            value = _commutative_result(mnemonic, a, b)
        write_operand(state, ctx, ops[0], value, obs)
        if mnemonic == "xor" and a == b:
            # Zero idiom: the flags are those of comparing zero with zero.
            state.flags = ZERO_FLAGS
        elif mnemonic in ("and", "or") and a == b:
            # SF/ZF/PF reflect the value; CF and OF are cleared: exactly
            # the flag state of `cmp value, 0`.
            state.flags = ("cmp", a, ("imm", 0))
        else:
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
        if mnemonic == "sub" and a == b:
            # Zero idiom: same flag state as xor r, r.
            state.flags = ZERO_FLAGS
            state.carry = ("cf0",)
        else:
            state.flags = ("flags", mnemonic, a, b)
            # The borrow out of sub is the unsigned comparison of its operands.
            state.carry = (
                ("lt_u", a, b) if mnemonic == "sub" else ("carry", mnemonic, a, b)
            )
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
        if a == b:
            state.flags = ZERO_FLAGS
        else:
            state.flags = ("cmp", a, b)
        # `x < x` and `x < 0` (unsigned) are always false.
        if b in (a, ("imm", 0)):
            state.carry = ("cf0",)
        else:
            state.carry = ("lt_u", a, b)
    elif mnemonic == "test" and len(ops) == 2:
        a = read_operand(state, ctx, ops[0])
        b = read_operand(state, ctx, ops[1])
        if a == b:
            # `test r, r` sets SF/ZF/PF from the value and clears CF/OF:
            # exactly the flag state of `cmp r, 0`.
            state.flags = ("cmp", a, ("imm", 0))
        else:
            state.flags = ("test", *_vsort(a, b))
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
    elif mnemonic == "pop" and len(ops) == 1:
        esp = state.read_reg("esp")
        if ctx.trace is not None:
            ctx.trace.append(("r", esp, 4, "pop"))
        write_operand(
            state,
            ctx,
            ops[0],
            ("load", esp, "stack", _load_tag(ctx, esp, 4, "pop")),
            obs,
        )
        state.write_reg("esp", esp_add(esp, 4))
    elif mnemonic == "leave":
        ebp = state.read_reg("ebp")
        if ctx.trace is not None:
            ctx.trace.append(("r", ebp, 4, "pop"))
        state.write_reg("ebp", ("load", ebp, "stack", _load_tag(ctx, ebp, 4, "pop")))
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
        reads, writes, _writes_memory = STRING_OPS[mnemonic]
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
    _commit_clobber(ctx, ("resync", idx))


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


# One-sided instructions that are never unobservable: control flow, the
# stack discipline (push/pop/leave/enter), x87 (stack-shape effects), and
# instructions that can fault on operand values (division).
_ONE_SIDED_BLACKLIST = frozenset(
    {"leave", "enter", "call", "ret", "jmp", "int3", "div", "idiv"}
    | set(JCC_MNEMONICS)
    | {"loop", "loope", "loopne", "jcxz", "jecxz"}
    | set(STRING_OPS)
)


def _one_sided_push_ok(state: SideState, ctx: Context, ins, idx: int) -> bool:
    """One side spills a register the other side never needed (a save
    around a region, or a scratch spill). The slot is private: it lies
    strictly below the entry stack pointer, no frame pointer has escaped,
    and the spill must be reclaimed before any call (a pushed value still
    live at a call would be an argument). The store is committed so later
    reads of the slot alias correctly."""
    value = read_operand(state, ctx, ins.operands[0])
    new_esp = esp_add(state.read_reg("esp"), -4)
    root, offset = _unwind_spadd(new_esp)
    if root != ("init", "sp") or offset >= 0 or ctx.stack_escaped:
        return False
    if _frame_pointer_value(value):
        return False
    obs = [("store", new_esp, "stack", value)]
    state.write_reg("esp", new_esp)
    tag = ("mem", ("scratch", idx), 0)
    ctx.mem_events.append((tag, (new_esp, 4, "push")))
    ctx.gen = tag
    ctx.scratch_pushes.append([state, offset, value, tag])
    _invalidate_save_slots(ctx, obs)
    ctx.categories.add("callee_save_substitution")
    return True


def _one_sided_pop_ok(state: SideState, ctx: Context, ins) -> bool:
    """Reclaim of a one-sided spill (or a plain scratch read): only from
    the function's own private scratch. When it provably reads back an
    intact one-sided push, the popped register regains the exact pushed
    value, so callee-save round-trips stay externally clean."""
    if ins.operands[0][0] != "reg":
        return False
    esp = state.read_reg("esp")
    root, offset = _unwind_spadd(esp)
    if root != ("init", "sp") or offset >= 0 or ctx.stack_escaped:
        return False
    tag = _load_tag(ctx, esp, 4, "pop")
    value: Value = ("load", esp, "stack", tag)
    for k, record in enumerate(ctx.scratch_pushes):
        if record[0] is state and record[1] == offset:
            if record[3] == tag:
                value = record[2]
            del ctx.scratch_pushes[k]
            break
    state.write_reg(ins.operands[0][1], value)
    state.write_reg("esp", esp_add(esp, 4))
    ctx.categories.add("callee_save_substitution")
    return True


def _one_sided_ok(
    state: SideState, other: SideState, ctx: Context, idx: int, line: str
) -> bool:
    # pylint: disable=too-many-return-statements
    """Execute an instruction that exists on only one side. Any instruction
    with no observable effect (no store, call, branch or return) is allowed:
    its register and flag writes are validated downstream by the observables
    that consume them, or by the end-of-run divergence rules. A memory read
    may fault, so it incurs a trap-parity obligation: the other side must
    read the same address at the same memory generation somewhere in the
    same verification scope (the folded-load case). Control flow, stack
    adjustments, x87 and potentially-faulting arithmetic stay excluded."""
    if DATA_LINE_RE.match(line):
        return False
    try:
        ins = parse_instruction(line)
    except (Reject, IndexError, KeyError, ValueError, TypeError):
        return False
    if ins.prefix or ins.mnemonic in _ONE_SIDED_BLACKLIST:
        return False
    if ins.mnemonic == "nop":
        ctx.categories.add("dead_operation")
        return True
    if ins.mnemonic.startswith("f"):
        return False
    try:
        if ins.mnemonic == "push" and len(ins.operands) == 1:
            return _one_sided_push_ok(state, ctx, ins, idx)
        if ins.mnemonic == "pop" and len(ins.operands) == 1:
            return _one_sided_pop_ok(state, ctx, ins)
    except (Reject, IndexError, KeyError, ValueError, TypeError):
        return False
    reads_before = len(state.load_log)
    log_snapshot = set(state.load_log) if state.load_log else set()
    obs: list = []
    try:
        execute(state, ctx, idx, ins, obs)
        guard_state_size(state, ctx)
    except (Reject, IndexError, KeyError, ValueError, TypeError):
        return False
    if obs:
        return False
    if len(state.load_log) > reads_before:
        for entry in state.load_log - log_snapshot:
            ctx.load_obligations.append((other, *entry))
        ctx.categories.add("load_folding")
    else:
        ctx.categories.add("dead_operation")
    return True


def _load_obligations_met(ctx: Context) -> bool:
    """Discharge the trap-parity obligations of one-sided memory reads:
    the other side must have read the same address at the same memory
    generation somewhere in the current verification scope."""
    return all(
        (address, gen) in other.load_log for other, address, gen in ctx.load_obligations
    )


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
                other_side = orig if line_o is None else recomp
                line = line_r if line_o is None else line_o
                assert line is not None
                if not _one_sided_ok(side, other_side, ctx, idx, line):
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
                    continue
                if not fully_synced(orig, recomp):
                    if recorder is not None:
                        recorder.mark_inconclusive(
                            "unsupported_instruction", index_o, index_r
                        )
                    return False
                resync((orig, recomp), idx, ctx)
                continue

            guard_state_size(orig, ctx)
            guard_state_size(recomp, ctx)

            if _callee_save_swap(ctx, ins_o, ins_r, obs_o, obs_r, orig, recomp):
                # The pushed values differ (that is the point of the swap),
                # but the slot and width agree: commit from the orig side.
                _commit_memory(ctx, obs_o, idx)
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

            _commit_memory(ctx, obs_o, idx)

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
        if not _load_obligations_met(ctx):
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
    if len(mem[2]) == 1 and not mem[4] and isinstance(mem[3], int):
        value, scale = mem[2][0]
        if scale == 1:
            root, offset = _unwind_spadd(value)
            return (root, offset + mem[3])
    return None


def _ranges_disjoint(a_disp, a_width, b_disp, b_width) -> bool:
    if isinstance(a_disp, int) and isinstance(b_disp, int):
        if a_width is None or b_width is None:
            return False
        return a_disp + a_width <= b_disp or b_disp + b_width <= a_disp
    if a_disp == b_disp:
        return False
    # Alpha-renamed frame slots: distinct slot ids are distinct locals
    # (their non-overlap is validated by _slots_consistent).
    return (
        isinstance(a_disp, tuple)
        and isinstance(b_disp, tuple)
        and a_disp[0] == b_disp[0] == "slot"
    )


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
    clone.load_log = set(state.load_log)
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
    # Whether a pointer into the function's own frame may have escaped on
    # some path reaching this point (see Context.stack_escaped).
    escaped: bool = False


def _clone_cfg_state(state: _CfgState) -> _CfgState:
    return _CfgState(
        _clone_state(state.orig),
        _clone_state(state.recomp),
        state.memory,
        state.escaped,
    )


_JOIN_ATTRS = ("flags", "carry", "fpu_flags")


def _join_states(
    entry: _CfgState,
    incoming: _CfgState,
    block: int,
) -> _CfgState | None:
    # pylint: disable=too-many-return-statements,too-many-locals
    # pylint: disable=too-many-branches
    """Merge an incoming state pair into a block's entry pair. Returns the
    (possibly new) entry pair, or None if the states cannot be merged
    (differing x87 shapes).

    Every storage node (each side's register families, flag values and x87
    slots) is keyed by its vector of values across the merge: nodes whose
    vectors are identical held provably equal values on every incoming
    edge, so they share one phi symbol — including nodes on *different*
    sides and in *different* registers. This keeps relational knowledge
    alive across joins when a live range is allocated to different
    registers on the two sides. A node whose value agrees on all edges
    keeps that value. Phi symbols are keyed by the class's canonical node
    index; classes can only refine as more edges arrive, so the fixpoint
    terminates."""
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
    if entry_o.x87.epoch != entry_r.x87.epoch:
        return None
    if in_o.x87.epoch != in_r.x87.epoch:
        return None
    out_o = _clone_state(entry_o)
    out_r = _clone_state(entry_r)
    if entry_o.x87.epoch != in_o.x87.epoch:
        # Paths through different call sites reach this block with different
        # x87 epochs. Control flow is paired, so both sides always arrive
        # via corresponding paths: a joined epoch keyed by the block keeps
        # deep-stack reads cross-equal (same reasoning as the memory phi).
        joined_epoch = ("x87_epoch_phi", block)
        out_o.x87.epoch = joined_epoch  # type: ignore[assignment]
        out_r.x87.epoch = joined_epoch  # type: ignore[assignment]

    # (entry value, incoming value, setter on the joined state)
    nodes: list[tuple[Value, Value, Callable[[Value], None]]] = []

    def reg_setter(state: SideState, family: str) -> Callable[[Value], None]:
        return lambda value: state.regs.__setitem__(family, value)

    def attr_setter(state: SideState, attr: str) -> Callable[[Value], None]:
        return lambda value: setattr(state, attr, value)

    def slot_setter(state: SideState, index: int) -> Callable[[Value], None]:
        return lambda value: state.x87.known.__setitem__(index, value)

    for entry_state, in_state, out_state in (
        (entry_o, in_o, out_o),
        (entry_r, in_r, out_r),
    ):
        for family in FAMILIES:
            nodes.append(
                (
                    entry_state.regs[family],
                    in_state.regs[family],
                    reg_setter(out_state, family),
                )
            )
        for attr in _JOIN_ATTRS:
            nodes.append(
                (
                    getattr(entry_state, attr),
                    getattr(in_state, attr),
                    attr_setter(out_state, attr),
                )
            )
        for index, entry_slot in enumerate(entry_state.x87.known):
            nodes.append(
                (
                    entry_slot,
                    in_state.x87.known[index],
                    slot_setter(out_state, index),
                )
            )

    classes: dict[tuple[Value, Value], int] = {}
    for n, (entry_value, in_value, setter) in enumerate(nodes):
        if entry_value == in_value:
            setter(entry_value)
            continue
        class_id = classes.setdefault((entry_value, in_value), n)
        setter(("phi", block, class_id))

    if entry.memory == incoming.memory:
        memory = entry.memory
    else:
        memory = ("cfg_mem_phi", block)
    return _CfgState(out_o, out_r, memory, entry.escaped or incoming.escaped)


def _states_equal(a: _CfgState, b: _CfgState) -> bool:
    return (
        a.memory == b.memory
        and a.escaped == b.escaped
        and all(
            x.regs == y.regs
            and x.flags == y.flags
            and x.carry == y.carry
            and x.fpu_flags == y.fpu_flags
            and x.x87.state_key() == y.x87.state_key()
            for x, y in ((a.orig, b.orig), (a.recomp, b.recomp))
        )
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
        ctx.stack_escaped = flow.escaped
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
                    continue
                if not fully_synced(orig_state, recomp_state):
                    if recorder is not None:
                        recorder.mark_inconclusive("unsupported_instruction", i, i)
                    return False
                resync((orig_state, recomp_state), i, ctx)
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
            _commit_memory(ctx, obs_o, i)

        last_kind = kinds[ends[block] - 1]
        if (
            last_kind == "ret"
            and orig_state.x87.state_key() != recomp_state.x87.state_key()
        ):
            return False
        if last_kind == "code" and ends[block] == total:
            # Falling out of the disassembled function is not a modeled exit.
            return False

        outgoing = _CfgState(orig_state, recomp_state, ctx.gen, ctx.stack_escaped)
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


# ---------------------------------------------------------------------------
# Isomorphic-CFG verification (structure-matched, alignment-free)
#
# The positional CFG verifier above requires the two sequences to have equal
# length and identical line-index branch structure. Register-allocation
# entropy breaks both: a folded load or an elided register copy shifts every
# following line and every crossing branch displacement. This verifier
# instead builds each side's basic-block graph independently, pairs blocks
# by control-flow structure (so branch targets compare as matched blocks,
# not displacement text), aligns each block pair's instructions locally,
# and runs the same paired symbolic execution with dataflow joins.


def _control_kind(line: str) -> str:
    if DATA_LINE_RE.match(line):
        return "data"
    mnemonic = line.partition(" ")[0]
    if mnemonic in JCC_MNEMONICS or mnemonic in (
        "loop",
        "loope",
        "loopne",
        "jcxz",
        "jecxz",
    ):
        return "jcc"
    if mnemonic in ("jmp", "ret"):
        return mnemonic
    return "code"


@dataclass
class _SideCfg:
    starts: list[int]
    ends: list[int]
    # Per block: role ("taken"/"fall"/"jmp"/"fallout") -> successor block
    # index, or "external" for a target outside the excerpt.
    succ: list[dict[str, int | str]]
    kinds: list[str]


def _build_side_cfg(asm: list[str], targets: list[int | None]) -> _SideCfg | None:
    """One side's basic-block structure, or None when the shape is outside
    this verifier's model (jump/data tables, invalid targets)."""
    total = len(asm)
    if total == 0 or len(targets) != total:
        return None
    kinds = [_control_kind(line) for line in asm]
    if "data" in kinds:
        return None
    leaders = {0}
    for i in range(total):
        target = targets[i]
        if target is not None:
            if not 0 <= target < total:
                return None
            leaders.add(target)
        if kinds[i] in ("jcc", "jmp", "ret") and i + 1 < total:
            leaders.add(i + 1)
    order = sorted(leaders)
    index = {start: n for n, start in enumerate(order)}
    ends = [order[n + 1] if n + 1 < len(order) else total for n in range(len(order))]
    succ: list[dict[str, int | str]] = []
    for n in range(len(order)):
        last = ends[n] - 1
        kind = kinds[last]
        edges: dict[str, int | str] = {}
        if kind == "jcc":
            target = targets[last]
            edges["taken"] = index[target] if target is not None else "external"
            if ends[n] < total:
                edges["fall"] = index[ends[n]]
            else:
                edges["fallout"] = "external"
        elif kind == "jmp":
            target = targets[last]
            edges["jmp"] = index[target] if target is not None else "external"
        elif kind == "ret":
            pass
        else:
            if ends[n] < total:
                edges["fall"] = index[ends[n]]
            else:
                edges["fallout"] = "external"
        succ.append(edges)
    return _SideCfg(starts=list(order), ends=ends, succ=succ, kinds=kinds)


def _pair_cfg_blocks(cfg_o: _SideCfg, cfg_r: _SideCfg) -> list[tuple[int, int]] | None:
    """Match the two sides' reachable blocks into a structural bijection,
    starting from the entry blocks and following same-role edges. Returns
    the matched pairs in discovery order, or None if the reachable graphs
    are not isomorphic."""
    map_o: dict[int, int] = {}
    map_r: dict[int, int] = {}
    order: list[tuple[int, int]] = []
    queue: list[tuple[int, int]] = [(0, 0)]
    while queue:
        block_o, block_r = queue.pop()
        seen_o = block_o in map_o
        seen_r = block_r in map_r
        if seen_o or seen_r:
            if map_o.get(block_o) != block_r or map_r.get(block_r) != block_o:
                return None
            continue
        map_o[block_o] = block_r
        map_r[block_r] = block_o
        order.append((block_o, block_r))
        edges_o = cfg_o.succ[block_o]
        edges_r = cfg_r.succ[block_r]
        if set(edges_o) != set(edges_r):
            return None
        for role, to_o in edges_o.items():
            to_r = edges_r[role]
            if (to_o == "external") != (to_r == "external"):
                return None
            if to_o != "external":
                assert isinstance(to_o, int) and isinstance(to_r, int)
                queue.append((to_o, to_r))
    return order


# Line-alignment costs (integers to keep DP ties exact): prefer exact text,
# then identical instruction shape (registers anonymized), then a shared
# mnemonic, then anything in the same observable class. A gap (one-sided
# line) costs more than a good pairing but less than two forced bad ones.
_SUB_EXACT = 0
_SUB_SKELETON = 1
_SUB_MNEMONIC = 4
_SUB_CLASS = 7
_GAP = 5

_X87_MEM_WRITERS_DP = frozenset({"fst", "fstp", "fist", "fistp", "fnstcw", "fbstp"})


@cache
def _dp_line_class(line: str) -> str:
    # pylint: disable=too-many-return-statements
    """Coarse observable class used to constrain the block-local alignment:
    lines with an observable effect only pair within their class and never
    go one-sided (the verifier would reject that anyway)."""
    mnemonic, _, _ = line.partition(" ")
    if mnemonic == "call":
        return "call"
    if mnemonic == "push":
        # Pushes pair with pushes, but may also go one-sided (a scratch
        # spill on one side only); the verifier gates the soundness.
        return "push"
    if mnemonic in STRING_OPS or mnemonic.startswith("rep"):
        return "store"
    try:
        ins = parse_instruction(line)
    except (Reject, IndexError, KeyError, ValueError, TypeError):
        return "opaque"
    if ins.prefix:
        return "store"
    if mnemonic in _X87_MEM_WRITERS_DP:
        return "store" if any(op[0] == "mem" for op in ins.operands) else "none"
    if mnemonic in ("cmp", "test"):
        return "none"
    if ins.operands and ins.operands[0][0] == "mem" and not mnemonic.startswith("j"):
        return "store"
    return "none"


@cache
def _dp_skeleton(line: str):
    """Instruction shape with register identities erased: mnemonic plus
    operand kinds, keeping immediates, symbols, widths, displacements and
    scale multisets."""
    try:
        ins = parse_instruction(line)
    except (Reject, IndexError, KeyError, ValueError, TypeError):
        return None
    shape: list[tuple] = []
    for op in ins.operands:
        kind = op[0]
        if kind == "reg":
            shape.append(("reg", REGISTERS[op[1]][1]))
        elif kind == "mem":
            _, size, seg, reg_terms, disp, syms = op
            shape.append(
                (
                    "mem",
                    size,
                    seg,
                    tuple(sorted(scale for _, scale in reg_terms)),
                    disp,
                    syms,
                )
            )
        else:
            shape.append(op)
    return (ins.prefix, ins.mnemonic, tuple(shape))


def _dp_sub_cost(line_o: str, line_r: str) -> float | None:
    if line_o == line_r:
        return _SUB_EXACT
    class_o = _dp_line_class(line_o)
    class_r = _dp_line_class(line_r)
    if class_o != class_r or class_o == "opaque":
        return None
    skeleton_o = _dp_skeleton(line_o)
    skeleton_r = _dp_skeleton(line_r)
    if skeleton_o is not None and skeleton_o == skeleton_r:
        return _SUB_SKELETON
    mnemonic_o = line_o.partition(" ")[0]
    mnemonic_r = line_r.partition(" ")[0]
    if mnemonic_o == mnemonic_r or (
        mnemonic_o in JCC_MNEMONICS and mnemonic_r in JCC_MNEMONICS
    ):
        return _SUB_MNEMONIC
    return _SUB_CLASS


def _align_block_lines(
    lines_o: list[str], lines_r: list[str]
) -> list[tuple[int | None, int | None]] | None:
    """Pair up two blocks' instructions with a cost-minimizing alignment.
    Returns block-local index pairs; None when the blocks cannot be aligned
    (observable-class counts differ, or the blocks are absurdly large)."""
    n, m = len(lines_o), len(lines_r)
    if n * m > 1_000_000:
        return None
    inf = float("inf")
    # cost[i][j]: best cost aligning lines_o[:i] with lines_r[:j].
    cost = [[inf] * (m + 1) for _ in range(n + 1)]
    cost[0][0] = 0.0
    gap_classes = ("none", "push")
    gap_o = [_GAP if _dp_line_class(line) in gap_classes else inf for line in lines_o]
    gap_r = [_GAP if _dp_line_class(line) in gap_classes else inf for line in lines_r]
    for i in range(1, n + 1):
        cost[i][0] = cost[i - 1][0] + gap_o[i - 1]
    for j in range(1, m + 1):
        cost[0][j] = cost[0][j - 1] + gap_r[j - 1]
    for i in range(1, n + 1):
        row = cost[i]
        prev = cost[i - 1]
        line_o = lines_o[i - 1]
        for j in range(1, m + 1):
            best = min(prev[j] + gap_o[i - 1], row[j - 1] + gap_r[j - 1])
            sub = _dp_sub_cost(line_o, lines_r[j - 1])
            if sub is not None:
                best = min(best, prev[j - 1] + sub)
            row[j] = best
    if cost[n][m] == inf:
        return None
    # Reconstruct.
    result: list[tuple[int | None, int | None]] = []
    i, j = n, m
    while i > 0 or j > 0:
        if i > 0 and j > 0:
            sub = _dp_sub_cost(lines_o[i - 1], lines_r[j - 1])
            if sub is not None and cost[i][j] == cost[i - 1][j - 1] + sub:
                result.append((i - 1, j - 1))
                i -= 1
                j -= 1
                continue
        if i > 0 and cost[i][j] == cost[i - 1][j] + gap_o[i - 1]:
            result.append((i - 1, None))
            i -= 1
            continue
        result.append((None, j - 1))
        j -= 1
    result.reverse()
    return result


def verify_isomorphic_cfg_effective_match(
    orig_asm: list[str],
    recomp_asm: list[str],
    orig_targets: list[int | None],
    recomp_targets: list[int | None],
    metadata: FunctionMetadata | None = None,
    orig_meta: list[InstructionMeta | None] | None = None,
    recomp_meta: list[InstructionMeta | None] | None = None,
    recorder: AnalysisRecorder | None = None,
) -> bool:
    """CFG verification that tolerates different instruction counts:
    per-side block graphs matched structurally, block contents aligned
    locally, one-sided unobservable instructions allowed. This proves
    register-allocation wobble in its full generality — renames composed
    with folded loads, elided copies and shifted branch displacements."""
    # pylint: disable=too-many-branches,too-many-statements,too-many-return-statements
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    cfg_o = _build_side_cfg(orig_asm, orig_targets)
    cfg_r = _build_side_cfg(recomp_asm, recomp_targets)
    if cfg_o is None or cfg_r is None:
        if recorder is not None:
            recorder.mark_inconclusive("unsupported_control_flow")
        return False
    pairs = _pair_cfg_blocks(cfg_o, cfg_r)
    if pairs is None:
        if recorder is not None:
            recorder.mark_inconclusive("unsupported_control_flow")
        return False
    pair_ids = {pair: n for n, pair in enumerate(pairs)}

    # Align every paired block's lines once, up front.
    alignments: dict[tuple[int, int], list[tuple[int | None, int | None]]] = {}
    any_shifted = False
    for block_o, block_r in pairs:
        start_o, end_o = cfg_o.starts[block_o], cfg_o.ends[block_o]
        start_r, end_r = cfg_r.starts[block_r], cfg_r.ends[block_r]
        aligned = _align_block_lines(orig_asm[start_o:end_o], recomp_asm[start_r:end_r])
        if aligned is None:
            if recorder is not None:
                recorder.mark_inconclusive("alignment_failure")
            return False
        # The block terminators (control lines) must pair with each other:
        # a one-sided branch or return breaks the matched structure.
        for local_o, local_r in aligned:
            kind_o = cfg_o.kinds[start_o + local_o] if local_o is not None else "code"
            kind_r = cfg_r.kinds[start_r + local_r] if local_r is not None else "code"
            if kind_o != kind_r or (local_o is None and kind_r != "code"):
                if recorder is not None:
                    recorder.mark_inconclusive("alignment_failure")
                return False
        if any(local_o is None or local_r is None for local_o, local_r in aligned):
            any_shifted = True
        alignments[(block_o, block_r)] = [
            (
                start_o + local_o if local_o is not None else None,
                start_r + local_r if local_r is not None else None,
            )
            for local_o, local_r in aligned
        ]

    entry: dict[tuple[int, int], _CfgState] = {
        (0, 0): _CfgState(
            SideState(rename_slots=False),
            SideState(rename_slots=False),
            ("cfg_mem_init",),
        )
    }
    pending: list[tuple[int, int]] = [(0, 0)]
    visits = 0

    def run_pair(pair: tuple[int, int]) -> bool:
        # pylint: disable=too-many-branches,too-many-statements
        # pylint: disable=too-many-return-statements,too-many-locals
        block_o, block_r = pair
        flow = _clone_cfg_state(entry[pair])
        orig_state, recomp_state = flow.orig, flow.recomp
        # Trap-parity scope for one-sided loads is the block run.
        orig_state.load_log = set()
        recomp_state.load_log = set()
        ctx = Context(gen=flow.memory, metadata=metadata, recorder=recorder)
        ctx.stack_escaped = flow.escaped
        edges_o = cfg_o.succ[block_o]
        edges_r = cfg_r.succ[block_r]
        for index_o, index_r in alignments[pair]:
            if index_o is None or index_r is None:
                if index_o is None:
                    assert index_r is not None
                    side, other_side = recomp_state, orig_state
                    line, position = recomp_asm[index_r], index_r
                else:
                    side, other_side = orig_state, recomp_state
                    line, position = orig_asm[index_o], index_o
                # A one-sided instruction can never store (any observable
                # rejects it), so the memory generation is unaffected.
                if not _one_sided_ok(side, other_side, ctx, position, line):
                    if recorder is not None:
                        recorder.mark_inconclusive(
                            "alignment_failure", index_o, index_r
                        )
                    return False
                continue
            line_o, line_r = orig_asm[index_o], recomp_asm[index_r]
            try:
                ins_o = parse_instruction(line_o)
                ins_r = parse_instruction(line_r)
                _record_operand_candidate(ctx, index_o, index_r, ins_o, ins_r)
                obs_o: list = []
                obs_r: list = []
                before_o = dict(orig_state.regs)
                before_r = dict(recomp_state.regs)
                state_before_o = _clone_state(orig_state)
                state_before_r = _clone_state(recomp_state)
                execute(orig_state, ctx, index_o, ins_o, obs_o)
                execute(recomp_state, ctx, index_o, ins_r, obs_r)
            except (Reject, IndexError, KeyError, ValueError, TypeError):
                if line_o != line_r:
                    if recorder is not None:
                        recorder.mark_inconclusive(
                            "unsupported_instruction", index_o, index_r
                        )
                    return False
                meta_o = orig_meta[index_o] if orig_meta is not None else None
                meta_r = recomp_meta[index_r] if recomp_meta is not None else None
                if _same_meta_effects(meta_o, meta_r) and _meta_step(
                    orig_state, recomp_state, meta_o, index_o
                ):
                    continue
                if not fully_synced(orig_state, recomp_state):
                    if recorder is not None:
                        recorder.mark_inconclusive(
                            "unsupported_instruction", index_o, index_r
                        )
                    return False
                resync((orig_state, recomp_state), index_o, ctx)
                continue

            guard_state_size(orig_state, ctx)
            guard_state_size(recomp_state, ctx)

            # Canonicalize local control-flow targets: the block pairing
            # already proved that both sides' edges lead to the same matched
            # blocks, so the displacement text is irrelevant. External
            # targets keep their raw text — those must match exactly.
            kind = cfg_o.kinds[index_o]
            if (
                kind in ("jcc", "jmp")
                and edges_o.get("taken" if kind == "jcc" else "jmp") != "external"
            ):
                for entries in (obs_o, obs_r):
                    for k, obs_entry in enumerate(entries):
                        if obs_entry[0] in CONTROL_TAGS - {"jmpind"}:
                            entries[k] = (*obs_entry[:-1], ("L", kind))

            if obs_o != obs_r:
                meta_o = orig_meta[index_o] if orig_meta is not None else None
                meta_r = recomp_meta[index_r] if recomp_meta is not None else None
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
                any(entry_obs[0] == "branch" for entry_obs in obs_o)
                and obs_o == obs_r
                and (
                    ins_o.mnemonic != ins_r.mnemonic
                    or state_before_o.flags != state_before_r.flags
                )
            ):
                ctx.categories.add("condition_inversion")
            if any(obs_entry[0] == "jmpind" for obs_entry in obs_o):
                if recorder is not None:
                    recorder.mark_inconclusive("unsupported_control_flow")
                return False

            # A direct edge outside the excerpt exposes the complete machine
            # state to code this proof does not inspect.
            if kind in ("jmp", "jcc") and (
                edges_o.get("taken" if kind == "jcc" else "jmp") == "external"
            ):
                if not _converged(orig_state, recomp_state):
                    if recorder is not None:
                        recorder.mark_inconclusive("unsupported_control_flow")
                    return False
            _commit_memory(ctx, obs_o, index_o)

        if not _load_obligations_met(ctx):
            if recorder is not None:
                recorder.mark_inconclusive("analysis_limit")
            return False

        last_kind = cfg_o.kinds[cfg_o.ends[block_o] - 1]
        if (
            last_kind == "ret"
            and orig_state.x87.state_key() != recomp_state.x87.state_key()
        ):
            return False
        if "fallout" in edges_o:
            # Falling out of the disassembled function is not a modeled exit.
            if recorder is not None:
                recorder.mark_inconclusive("unsupported_control_flow")
            return False

        outgoing = _CfgState(orig_state, recomp_state, ctx.gen, ctx.stack_escaped)
        if recorder is not None:
            recorder.reasons.update(ctx.categories)
        for role, to_o in edges_o.items():
            if to_o == "external":
                continue
            to_r = edges_r[role]
            assert isinstance(to_o, int) and isinstance(to_r, int)
            successor = (to_o, to_r)
            if successor not in entry:
                entry[successor] = _clone_cfg_state(outgoing)
                pending.append(successor)
            else:
                joined = _join_states(entry[successor], outgoing, pair_ids[successor])
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
            pair = pending.pop()
            visits += 1
            if visits > 8 * len(pairs) + 64:
                if recorder is not None:
                    recorder.mark_inconclusive("analysis_limit")
                return False
            if not run_pair(pair):
                return False
    except (Reject, RecursionError):
        if recorder is not None:
            recorder.mark_inconclusive("analysis_limit")
        return False
    if any_shifted and recorder is not None:
        recorder.reasons.add("instruction_reorder")
    return True
