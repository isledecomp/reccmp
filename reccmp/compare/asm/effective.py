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

import re
from dataclasses import dataclass, field
from functools import cache

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
    regs: dict[str, Value] = field(
        default_factory=lambda: {f: ("init", f) for f in FAMILIES}
    )
    flags: Value = ("init", "flags")
    fpu_flags: Value = ("init", "fpuflags")
    x87: X87Stack = field(default_factory=X87Stack)
    # The value eax held at each `ret`, validated at the end of the run.
    retvals: list[Value] = field(default_factory=list)

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


@dataclass
class Context:
    gen: int = 0  # memory generation, shared by both sides
    bump_requested: bool = False
    matched: list[Value] = field(default_factory=list)
    # Memoization for _tree_size, keyed by object identity. The keepalive
    # list pins the measured tuples so their ids cannot be recycled.
    size_cache: dict[int, int] = field(default_factory=dict)
    keepalive: list = field(default_factory=list)
    # When not None, every memory access performed by execute() is recorded
    # here as ("r"|"w", address value, width, is_stack_slot).
    trace: list | None = None


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
    for value in (*state.regs.values(), state.flags, state.fpu_flags):
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


# ---------------------------------------------------------------------------
# Symbolic execution of one side


def mem_address(state: SideState, op) -> Value:
    _, _, seg, reg_terms, disp, syms = op
    terms = tuple(
        sorted(
            ((state.read_reg(reg), scale) for reg, scale in reg_terms),
            key=repr,
        )
    )
    return ("mem", seg, terms, disp, syms)


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
        address = mem_address(state, op)
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


def canon_condition(cc: str, flags: Value) -> Value:
    """Canonical predicate for a condition code applied to a flag state, so
    that `cmp a, b` + jg equals `cmp b, a` + jl."""
    entry = CC_CANON.get(cc)
    if entry is not None and isinstance(flags, tuple) and flags[0] == "cmp":
        pred, swap = entry
        a, b = flags[1], flags[2]
        if pred in ("eq", "ne"):
            return (pred, _vsort(a, b))
        return (pred, b, a) if swap else (pred, a, b)
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
        write_operand(state, ctx, ops[0], ("addr", mem_address(state, ops[1])), obs)
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
            value = (mnemonic, *pair)
        write_operand(state, ctx, ops[0], value, obs)
        state.flags = ("flags", mnemonic, *pair)
    elif mnemonic == "imul" and len(ops) == 3:
        value = (
            "imul3",
            read_operand(state, ctx, ops[1]),
            read_operand(state, ctx, ops[2]),
        )
        write_operand(state, ctx, ops[0], value, obs)
        state.flags = ("flags", *value)
    elif mnemonic in ORDERED_BINOPS and len(ops) == 2:
        a = read_operand(state, ctx, ops[0])
        b = read_operand(state, ctx, ops[1])
        value = ("imm", 0) if (mnemonic == "sub" and a == b) else (mnemonic, a, b)
        write_operand(state, ctx, ops[0], value, obs)
        state.flags = ("flags", mnemonic, a, b)
    elif mnemonic in CARRY_BINOPS and len(ops) == 2:
        a = read_operand(state, ctx, ops[0])
        b = read_operand(state, ctx, ops[1])
        value = (mnemonic, a, b, state.flags)
        write_operand(state, ctx, ops[0], value, obs)
        state.flags = ("flags", *value)
    elif mnemonic in ("inc", "dec", "neg", "not") and len(ops) == 1:
        value = (mnemonic, read_operand(state, ctx, ops[0]))
        write_operand(state, ctx, ops[0], value, obs)
        if mnemonic != "not":
            state.flags = ("flags", *value)
    elif mnemonic == "cmp" and len(ops) == 2:
        state.flags = (
            "cmp",
            read_operand(state, ctx, ops[0]),
            read_operand(state, ctx, ops[1]),
        )
    elif mnemonic == "test" and len(ops) == 2:
        state.flags = (
            "test",
            *_vsort(read_operand(state, ctx, ops[0]), read_operand(state, ctx, ops[1])),
        )
    elif mnemonic in ("mul", "imul") and len(ops) == 1:
        acc, hi = _mul_registers(ops[0])
        pair = _vsort(state.read_reg(acc), read_operand(state, ctx, ops[0]))
        state.write_reg(acc, (mnemonic, "lo", *pair))
        state.write_reg(hi, (mnemonic, "hi", *pair))
        state.flags = ("flags", mnemonic, *pair)
    elif mnemonic in ("div", "idiv") and len(ops) == 1:
        acc, hi = _mul_registers(ops[0])
        divisor = read_operand(state, ctx, ops[0])
        dividend = (state.read_reg(hi), state.read_reg(acc))
        state.write_reg(acc, (mnemonic, "quot", dividend, divisor))
        state.write_reg(hi, (mnemonic, "rem", dividend, divisor))
        state.flags = ("undef_flags", idx)
    elif mnemonic == "cdq":
        state.write_reg("edx", ("cdq", state.read_reg("eax")))
    elif mnemonic == "cwde":
        state.write_reg("eax", ("cwde", state.read_reg("ax")))
    elif mnemonic == "sahf":
        state.flags = ("sahf", state.read_reg("ah"))
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
        obs.append(("call", read_operand(state, ctx, ops[0])))
        # The callee may take args in registers (thiscall/fastcall use ecx
        # and edx; both are also clobbered). Requiring ecx/edx equality at
        # every call would reject renames of dead caller-saved temps, so we
        # only require what flows into the call via checked channels (stack
        # pushes and memory). eax/ecx/edx come back as fresh paired values.
        for reg in ("eax", "ecx", "edx"):
            state.write_reg(reg, ("callret", idx, reg))
        state.write_reg("esp", ("callesp", idx))
        state.flags = ("callflags", idx)
        state.x87 = X87Stack(epoch=idx + 1)
        ctx.bump_requested = True
    elif mnemonic == "ret":
        obs.append(("retstack", ins.raw_operands, state.x87.state_key()[1:]))
        if state.x87.known:
            # x87 return value: st(0) must match; eax is scratch.
            obs.append(("retfpu", state.x87.known[0]))
        else:
            # A possible integer return value: validated at the end of the
            # run, when the full set of matched expressions is known.
            state.retvals.append(state.read_reg("eax"))
    elif mnemonic in JCC_MNEMONICS and len(ops) == 1:
        pred = canon_condition(JCC_MNEMONICS[mnemonic], state.flags)
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
        pred = canon_condition(mnemonic[3:], state.flags)
        write_operand(state, ctx, ops[0], ("setcc", pred), obs)
    elif mnemonic.startswith("cmov") and mnemonic[4:] in JCC_MNEMONICS.values():
        pred = canon_condition(mnemonic[4:], state.flags)
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
        and orig.fpu_flags == recomp.fpu_flags
        and orig.x87.state_key() == recomp.x87.state_key()
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
        state.fpu_flags = ("resync_fpuflags", idx)
        state.x87.known = [("resync_st", idx, i) for i in range(len(state.x87.known))]
    ctx.bump_requested = True


def _contained(value: Value, matched_repr: str) -> bool:
    return repr(value) in matched_repr


def _dead_or_contained(value: Value, matched_repr: str) -> bool:
    return _is_scratch(value) or _contained(value, matched_repr)


def _ins_split_ok(value_o: Value, value_r: Value, matched_repr: str) -> bool:
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
        and _dead_or_contained(value_o[1], matched_repr)
        and _dead_or_contained(value_r[1], matched_repr)
    )


def _retval_ok(value_o: Value, value_r: Value, matched_repr: str) -> bool:
    """Is the eax divergence at a `ret` acceptable? Since the return type is
    unknown, a differing eax is allowed only when the difference is provably
    dead data: untouched/clobbered scratch, values that were consumed by a
    matched expression (a void function's leftovers), or stale upper bits
    around an identical partial-register result."""
    if value_o == value_r:
        return True
    if _is_scratch(value_o) or _is_scratch(value_r):
        return True
    if _ins_split_ok(value_o, value_r, matched_repr):
        return True
    return _contained(value_o, matched_repr) and _contained(value_r, matched_repr)


# Caller-saved register families: dead at function end (eax is separately
# checked as the return value at every `ret`).
CALLER_SAVED = ("a", "c", "d")


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


def verify_effective_match(orig_asm: list[str], recomp_asm: list[str]) -> bool:
    """True if the two instruction sequences can be proven equivalent
    modulo register allocation, commutative-operand order and inverted
    compare/jump conditions."""
    # pylint: disable=too-many-branches,too-many-return-statements
    if len(orig_asm) != len(recomp_asm):
        return False

    orig = SideState()
    recomp = SideState()
    ctx = Context()

    try:
        for idx, (line_o, line_r) in enumerate(zip(orig_asm, recomp_asm)):
            if DATA_LINE_RE.match(line_o) or DATA_LINE_RE.match(line_r):
                if line_o != line_r:
                    return False
                continue

            try:
                ins_o = parse_instruction(line_o)
                ins_r = parse_instruction(line_r)
                obs_o: list = []
                obs_r: list = []
                ctx.bump_requested = False
                before_o = dict(orig.regs)
                before_r = dict(recomp.regs)
                execute(orig, ctx, idx, ins_o, obs_o)
                execute(recomp, ctx, idx, ins_r, obs_r)
            except (Reject, IndexError, KeyError, ValueError, TypeError):
                # Unsupported or malformed instruction: only allowed if both
                # sides are textually identical and semantically synchronized.
                if line_o != line_r or not fully_synced(orig, recomp):
                    return False
                resync((orig, recomp), idx, ctx)
                ctx.gen += 1
                continue

            guard_state_size(orig, ctx)
            guard_state_size(recomp, ctx)

            if obs_o != obs_r:
                return False
            ctx.matched.extend(obs_o)

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
                    ctx.matched.append(value)

            if ctx.bump_requested:
                ctx.gen += 1

        # Values still diverged at the end must be dead. We accept a
        # divergent register only if both of its values were consumed by
        # something that was proven equal across the two sides (e.g. the
        # operands of a canonicalized compare, or a value stored to memory).
        for family in FAMILIES:
            if orig.regs[family] == recomp.regs[family]:
                ctx.matched.append(orig.regs[family])
        for slot_o, slot_r in zip(orig.x87.known, recomp.x87.known):
            if slot_o == slot_r:
                ctx.matched.append(slot_o)

        matched_repr = "\n".join(repr(m) for m in ctx.matched)

        for family in FAMILIES:
            value_o, value_r = orig.regs[family], recomp.regs[family]
            if value_o == value_r:
                continue
            if _ins_split_ok(value_o, value_r, matched_repr):
                continue
            allow_scratch = family in CALLER_SAVED
            for value in (value_o, value_r):
                if allow_scratch and _is_scratch(value):
                    continue
                if not _contained(value, matched_repr):
                    return False

        for value_o, value_r in zip(orig.retvals, recomp.retvals):
            if not _retval_ok(value_o, value_r, matched_repr):
                return False
    except (Reject, RecursionError):
        return False

    if orig.x87.state_key()[1:] != recomp.x87.state_key()[1:]:
        return False
    if len(orig.x87.known) != len(recomp.x87.known):
        return False
    for slot_o, slot_r in zip(orig.x87.known, recomp.x87.known):
        if slot_o != slot_r:
            if not (
                _contained(slot_o, matched_repr) and _contained(slot_r, matched_repr)
            ):
                return False

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
    unparseable text) is a scheduling barrier."""
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
    state.fpu_flags = ("havoc_fpuflags", idx)
    state.x87 = X87Stack(epoch=-idx - 1)


def sequence_effects(asm: list[str]) -> list[LineEffects] | None:
    """Symbolically execute one instruction sequence and return a per-line
    effect summary with memory addresses resolved to symbolic values.
    Returns None if the sequence cannot be analyzed at all."""
    state = SideState()
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
        stack_kind = a_stack or b_stack
        other = _flatten_mem(b_addr if a_stack else a_addr)
        if _is_pure_global(other):
            # A stack slot never overlaps a named global.
            return True
        if stack_kind == "push":
            # A push writes to fresh space below the stack pointer, where no
            # other live memory (heap, globals, caller stack, locals) can
            # be. Only another stack-pointer-derived access could reach it.
            return not any(_stack_rooted(v) for v, _ in other[2])
        return False

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
