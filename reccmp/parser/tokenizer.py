"""Tokenizer for C/C++ code files and functions for working with the tokens.
This is intended as a precursor to reccmp annotation parsing, but there may be general-purpose applications.

The first step is `tokenize_code_file()` to get the list of tokens.

`resolve_scopes()` identifies pairs of curly brackets. This provides the start and end position of functions
and class/struct/namespace scopes in a single pass.

`get_namespaces_from_scopes()` returns the name of a class/struct/namespace that should attach to each bracket pair.

`get_newlines_from_text()` provides a pre-processed to use with `get_line_column_pos()` to report the human-friendly
position for warnings and errors."""

import bisect
import re
import string
import enum
from sys import maxsize as MAX_INT


class TokenType(enum.IntEnum):
    CURLY_OPEN = enum.auto()
    CURLY_CLOSE = enum.auto()
    PPC_IF = enum.auto()
    PPC_ELSE = enum.auto()
    PPC_ELIF = enum.auto()
    PPC_END = enum.auto()
    PPC_OTHER = enum.auto()
    SEMICOLON = enum.auto()
    EQUAL = enum.auto()
    LINE_COMMENT = enum.auto()
    BLOCK_COMMENT = enum.auto()
    STRING = enum.auto()
    CHAR = enum.auto()
    CODE = enum.auto()
    WHITESPACE = enum.auto()


r_codeSplitter = re.compile(
    r"""
\{|\}|=|;|
//[^\n]*|
/\*.*?\*/|
L\"[^\"\n\\]*(?:\\.[^\"\n\\]*)*[\"\n]|
\"[^\"\n\\]*(?:\\.[^\"\n\\]*)*[\"\n]|
L\'[^'\n\\]*(?:\\.[^'\n\\]*)*['\n]|
\'[^'\n\\]*(?:\\.[^'\n\\]*)*['\n]|
\#\s*(\w+)(?:[^\n\\]+|\\\n|\\)*
""",
    flags=re.X | re.DOTALL,
)

CodeToken = tuple[int, int, TokenType]
"""Start position (inclusive), end position (exclusive), and type for this token.
Using regular tuples is fastest on pure Python, so this type alias will serve to
document function parameters where we expect tokens. Dataclasses with slots came
close to matching performance, but they are not hashable/immutable."""


def tokenize_code_file(text: str) -> list[CodeToken]:
    tokens = []

    # Start of code token between delimiters.
    start = 0

    # Pull out the iterator to a variable so the
    # digit separator case can overwrite it.
    matches = r_codeSplitter.finditer(text)

    # The inner loop runs to exhaustion unless the digit separator case replaces
    # the iterator, which breaks out so the outer loop can pick up the new one.
    while True:
        for match in matches:
            pos, stop = match.span()
            first = text[pos]

            if first == "{":
                token_type = TokenType.CURLY_OPEN
            elif first == "}":
                token_type = TokenType.CURLY_CLOSE
            elif first == "=":
                token_type = TokenType.EQUAL
            elif first == ";":
                token_type = TokenType.SEMICOLON
            elif first == '"':
                token_type = TokenType.STRING
            elif first == "'":
                if pos and text[pos - 1] in string.hexdigits:
                    # Reset the iterator to skip the single quote.
                    # Do not skip delimiters inside this rejected CHAR token.
                    matches = r_codeSplitter.finditer(text, pos + 1)
                    break

                token_type = TokenType.CHAR
            elif first == "#":
                ppc_name = match.group(1).lower()
                if ppc_name.startswith("if"):
                    token_type = TokenType.PPC_IF
                elif ppc_name.startswith("elif"):
                    token_type = TokenType.PPC_ELIF
                elif ppc_name == "else":
                    token_type = TokenType.PPC_ELSE
                elif ppc_name == "endif":
                    token_type = TokenType.PPC_END
                else:
                    token_type = TokenType.PPC_OTHER

            else:
                second = text[pos + 1]
                if first == "L":
                    token_type = TokenType.STRING if second == '"' else TokenType.CHAR
                else:
                    token_type = (
                        TokenType.LINE_COMMENT
                        if second == "/"
                        else TokenType.BLOCK_COMMENT
                    )

            if start < pos:
                # Skip if this is entirely whitespace
                code = text[start:pos].lstrip()
                if code:
                    code_start = pos - len(code)
                    tokens.append(
                        (code_start, code_start + len(code.rstrip()), TokenType.CODE)
                    )

            tokens.append((pos, stop, token_type))
            start = stop
        else:
            # No more tokens
            break

    if start < len(text):
        code = text[start:].lstrip()
        if code:
            code_start = len(text) - len(code)
            tokens.append((code_start, code_start + len(code.rstrip()), TokenType.CODE))

    return tokens


def get_newlines_from_text(text: str) -> list[int]:
    return [-1] + [m.start() for m in re.finditer(r"\n", text)]


def get_line_column_pos(newlines: list[int], offset: int) -> tuple[int, int]:
    """Calculate 1-based (line, column) position for the given absolute position.
    This is not needed for most tokens and would be expensive to do in the tokenizer.
    The `newlines` parameter is the precalculated result from get_newlines_from_text().
    """
    i = bisect.bisect_left(newlines, offset)
    if i == 0:
        return (1, 1)

    pos = newlines[i - 1]
    return (i, offset - pos)


def get_token_index(tokens: list[CodeToken], pos: int) -> int:
    """Returns the first index of `tokens` where the token start position is at or before `pos`.
    Whitespace between tokens may be deleted. If `pos` points to whitespace not contained in a
    token, we return the index of the previous token."""
    return bisect.bisect_right(tokens, (pos, MAX_INT)) - 1


def find_scope_keywords(text: str) -> list[int]:
    """Returns start positions for substrings "struct", "namespace", and "class" in the string `text`."""
    output = []

    scope_keywords = {"struct", "namespace", "class"}

    for keyword in scope_keywords:
        pos = text.find(keyword)
        while pos != -1:
            output.append(pos)
            pos = text.find(keyword, pos + len(keyword))

    return output


def find_code_keywords(text: str, tokens: list[CodeToken]) -> list[int]:
    """Return the index of each CODE token that contains the word "struct", "namespace", or "class"."""

    # Use a set because a CODE token could contain the keyword twice.
    # We will filter these out in a further step.
    code_keywords = set()
    for pos in find_scope_keywords(text):
        # Which token contains this position?
        index = get_token_index(tokens, pos)

        # CODE tokens only. Reject matches that are inside a comment or string token.
        if tokens[index][2] == TokenType.CODE:
            code_keywords.add(index)

    return sorted(code_keywords)


DECLARATION_END_TOKENS = {
    TokenType.CURLY_OPEN,
    TokenType.CURLY_CLOSE,
    TokenType.SEMICOLON,
    TokenType.EQUAL,
}


def find_declaration_end(tokens: list[CodeToken], index: int) -> int | None:
    """Starting at `index`, find the next token in `tokens` that ends a scope declaration."""
    for end in range(index, len(tokens)):
        if tokens[end][2] in DECLARATION_END_TOKENS:
            return end

    return None


def find_declaration_chains(
    text: str, tokens: list[CodeToken]
) -> list[tuple[int, int]]:
    """Find each chain of indices in `tokens` where a named scope declaration could exist."""
    chains: list[tuple[int, int]] = []
    for start in find_code_keywords(text, tokens):
        # If we are inside the range of the most-recently captured chain,
        # we know that it will end at the same point.
        # Our goal on this step is to capture the widest possible range of CODE tokens
        # and then refine it further to find the true scope name if it exists.
        if chains and start <= chains[-1][1]:
            continue

        end = find_declaration_end(tokens, start)
        # If we did not find a token, we must be at the end of the list.
        # No future chains are possible.
        if end is None:
            break

        chains.append((start, end))

    return chains


r_lastScopeKeyword = re.compile(r".*\b(?:struct|namespace|class)\s", flags=re.DOTALL)
"""More precise match for a keyword that begins a scope: it must not be asubstring in larger identifier."""


r_scopeName = re.compile(r"(?P<name>\w+)\s*(?::(?!:).*)?$", flags=re.DOTALL)
"""Match the scope name (qualified or not) that is either the last identifier in the string,
or the last before a single ':' character demarcates the base class list."""


def find_declaration_name(
    text: str, tokens: list[CodeToken], start: int, end: int
) -> str | None:
    """Find the name for the named scope that begins somewhere between the CODE token at index `start`
    and then CURLY_OPEN token at index `end`. If there are multiple keywords that could be the start
    of the scope, choose the one closest to the end.
    """
    if start + 1 == end:
        # If the scope declaration is entirely within one CODE token, save a split.
        code = text
        code_start, code_stop, _ = tokens[start]
    else:
        # Build a synthetic string with only text from CODE tokens,
        # excluding any comments or other content.
        code = " ".join(
            text[start:stop]
            for start, stop, token_type in tokens[start:end]
            if token_type == TokenType.CODE
        )
        code_start, code_stop = 0, len(code)

    # Find the last instance of the keyword "class", "struct", or "namespace" that is
    # not a substring in a longer word (e.g. "subclass").
    # Stop before the ":" character that begins the superclass list for a class.
    keyword = r_lastScopeKeyword.match(code, code_start, code_stop)
    if keyword is None:
        return None

    # Find the scope name between
    if match := r_scopeName.search(code, keyword.end(), code_stop):
        return match.group(1)

    return None


def get_namespaces_from_scopes(
    text: str,
    tokens: list[CodeToken],
    scopes: dict[int, int],
) -> list[tuple[int, int, str]]:
    """Using the known scope enclosures, find which ones are the start of a
    struct, class, or namespace. Return the name and range of positions where each
    named scope is active."""
    declarations = find_declaration_chains(text, tokens)

    names: list[tuple[int, int, str]] = []
    for index, end in declarations:
        # Does this chain of tokens end on a CURLY_OPEN token that is the start of a bracket pair?
        # If not, skip. We did not detect a scope starting here, and so there could not be a name for it.
        scope_start = tokens[end][0]
        if scope_start not in scopes:
            continue

        if (name := find_declaration_name(text, tokens, index, end)) is not None:
            names.append((scope_start, scopes[scope_start], name))

    return names


CURLY_TOKENS = {TokenType.CURLY_OPEN, TokenType.CURLY_CLOSE}

PPC_TOKENS = {
    TokenType.PPC_IF,
    TokenType.PPC_ELIF,
    TokenType.PPC_ELSE,
    TokenType.PPC_END,
}


SCOPE_TOKENS = CURLY_TOKENS | PPC_TOKENS


def scope_tokens_only(tokens: list[CodeToken]) -> list[CodeToken]:
    return [x for x in tokens if x[2] in SCOPE_TOKENS]


def pair_brackets(
    tokens: list[CodeToken],
    *,
    enable_ppc: bool,
) -> tuple[list[tuple[int, int]], list[CodeToken]]:
    """Pair up curly bracket tokens. Keep searching until we can't pair any more.
    Returns:
    [0]: List of new pairs found.
    [1]: Remaining tokens after paired tokens are removed.
    If enable_ppc is True, brackets can only be paired if they are both inside the same PPC branch.
    If it is false, we ignore PPC tokens entirely and assume all branches are enabled,
    even if this makes no sense. We do not examine or evaluate the PPC expressions at all.
    """
    ranges = []
    stack: list[CodeToken] = []
    output: list[CodeToken] = []
    for x in tokens:
        if x[2] == TokenType.CURLY_CLOSE:
            if stack:
                y = stack.pop()
                ranges.append((y[0], x[0]))
            else:
                output.append(x)
        elif x[2] == TokenType.CURLY_OPEN:
            stack.append(x)
        elif enable_ppc and x[2] in PPC_TOKENS:
            output.extend(stack)
            output.append(x)
            stack.clear()

    output.extend(stack)
    return (ranges, output)


def find_collapsible_ppc_branches(remain: list[CodeToken]) -> set[int]:
    """Find PPC blocks where every option (branch) introduces the same sequence of curly brackets.
    In other words, the net effect on bracket pairing is the same no matter how the preprocessor
    expressions are evaluated.

    If any blocks qualify, enable the curly brackets from the first branch (chosen arbitrarily)
    and return a list of tokens (by their start position) to remove from the list, including any
    `#if`, `#else`, or `#endif tokens that wrap the PPC blocks.

    A single pass can only mask out PPC blocks that are not interrupted by nesting.
    """
    interrupted = False
    global_mask = set()
    mask = set()
    # Each leg records its curly brackets as (offset, token) so we can compare
    # branches by their bracket *sequence*, not just how many brackets they have.
    legs: list[list[tuple[int, TokenType]]] = [[]]

    for start, _, token in remain:
        # Build a list of all tokens that will be affected in this PPC block.
        mask.add(start)

        if token in (TokenType.CURLY_OPEN, TokenType.CURLY_CLOSE):
            legs[-1].append((start, token))

        elif token == TokenType.PPC_IF:
            # New block begins here. If one was already started,
            # it can no longer be condensed on this pass.
            interrupted = False
            mask = {start}
            legs = [[]]

        elif token in (TokenType.PPC_ELSE, TokenType.PPC_ELIF):
            # New branch begins here
            legs.append([])

        elif token == TokenType.PPC_END:
            # `not interrupted`: branches are all at the same PPC level
            # `len(legs) > 1`: there is more than one option, OR
            # `not signature`: the block has no brackets
            # signature match: every branch has the same bracket sequence
            # (same count AND same open/close direction). Folding one branch in
            # for another is only valid if they are structurally identical.
            # Rejects nonsense like `#if { #else } #endif`.
            signature = [token for _, token in legs[0]]
            if (
                not interrupted
                and (len(legs) > 1 or not signature)
                and all([t for _, t in leg] == signature for leg in legs)
            ):
                # Retain only the curly brackets from the first branch.
                keepers = {start for start, _ in legs[0]}
                # All others in this block will be deleted.
                global_mask |= mask - keepers

            interrupted = True
            legs = [[]]
            mask.clear()

    return global_mask


def all_curly_paired(tokens: list[CodeToken]) -> bool:
    for x in tokens:
        if x[2] in CURLY_TOKENS:
            return False

    return True


def check_naive_pairing(
    bracket_pairs: list[tuple[int, int]], tokens: list[CodeToken]
) -> bool:
    """Check the new bracket pairs from `pair_brackets(enable_ppc=False)`
    against every sequence of preprocessor tokens (blocks).

    Allow these patterns:

        1. Brackets are completely outside the block
            { } #if #endif

        2. Brackets are confined to one branch of the block
            #if {} #endif, #if { } #else #endif

        3. Brackets enclose the entire block
            { #if #else #endif }

        4. One bracket is inside a block, but it has only one branch
            { #if } #endif

    If any of these patterns are found, reject all pairings:

        5. Brackets are in different branches of the same block
            #if { #else } #endif

        6. One bracket is inside a block with multiple branches
            { #if } #else #endif
    """
    # Start by collecting the position of each preprocessor token in a block.
    stack: list[list[int]] = []
    blocks: list[list[int]] = []
    for start, _, token in tokens:
        if token == TokenType.PPC_IF:
            stack.append([start])
        elif token in (TokenType.PPC_ELSE, TokenType.PPC_ELIF):
            if stack:
                stack[-1].append(start)
        elif token == TokenType.PPC_END:
            if stack:
                stack[-1].append(start)
                block = stack.pop()
                # We only need to check blocks with multiple branches.
                # It is assumed that naive pairings will include pattern 4.
                if len(block) > 2:
                    blocks.append(block)

    # Test each pairing against every PPC block with multiple branches.
    for open_pos, close_pos in bracket_pairs:
        for block in blocks:
            # The brackets must enclose every preprocessor token in the
            # block (pattern 3) or none of them (patterns 1 and 2).
            # Otherwise: (patterns 5 and 6) reject all pairings.
            enclosed = sum(open_pos < pos < close_pos for pos in block)
            if 0 < enclosed < len(block):
                return False

    return True


def resolve_scopes(
    tokens: list[CodeToken],
) -> tuple[dict[int, int], list[CodeToken]]:
    """Pair up curly brackets in the entire file to the best of our ability.
    Returns a map of (start -> stop) regions of the paired brackets.
    We may not be able to pair all brackets because of invalid syntax
    or preprocessor sequences that are not reducible.
    If this occurs, we also return a list of brackets and PPC tokens that we
    are unable to handle. The caller can decide how to alert the user."""
    remain = scope_tokens_only(tokens)

    out_ranges = []

    # 10 iterations chosen arbitrarily simply to avoid an unexpected infinite loop.
    for _ in range(10):
        reduced_this_step = False
        # Match any curly bracket pairs that are next to each other.
        new_ranges, new_remain = pair_brackets(remain, enable_ppc=True)
        if new_ranges:
            out_ranges.extend(new_ranges)
            remain = new_remain
            reduced_this_step = True

        # If all curly brackets have been matched, we are done.
        # There may still be PPC tokens in the list, but none can block a bracket match,
        # so they are not returned.
        if all_curly_paired(new_remain):
            remain = []
            break

        # Can we simply enable all PPC regions and match remaining brackets?
        new_ranges, new_remain = pair_brackets(remain, enable_ppc=False)
        # This is only allowed if:
        # 1. Doing this allows us to pair all remaining brackets.
        # 2. No pairing joins two regions separated by #else/#elif.
        # `new_remain` has had its PPC tokens removed, so use `remain`.
        if not new_remain and check_naive_pairing(new_ranges, remain):
            out_ranges.extend(new_ranges)
            remain = new_remain
            break

        mask = find_collapsible_ppc_branches(remain)
        if mask:
            remain = [
                (start, stop, token)
                for start, stop, token in remain
                if start not in mask
            ]
            reduced_this_step = True

        if not reduced_this_step:
            break

    return (dict(out_ranges), remain)
