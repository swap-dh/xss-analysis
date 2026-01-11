import io
import re
import tokenize
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class Issue:
    line: int      # 0-based
    col: int       # 0-based
    end_col: int   # 0-based
    message: str
    severity: int  # 1=Error, 2=Warning


# -----------------------
# Flask + input() case library
# -----------------------

# Source: Flask external input + python input()
SOURCE_CALL_PATTERNS = [
    re.compile(r"\binput\s*\("),

    # Flask
    re.compile(r"\brequest\.(args|form|values)\.get\s*\("),
    re.compile(r"\brequest\.(args|form|values)\s*\["),  # request.args["q"]
    re.compile(r"\brequest\.get_json\s*\("),
    re.compile(r"\brequest\.json\b"),
]

# Sink: places where output likely reaches client (XSS-relevant)
SINK_CALL_PATTERNS = [
    re.compile(r"\brender_template_string\s*\("),
    re.compile(r"\bResponse\s*\("),
    re.compile(r"\bmake_response\s*\("),
    re.compile(r"\bMarkup\s*\("),  # if tainted goes into Markup -> dangerous
]

# Sanitizer: escape / clean
SANITIZER_CALL_PATTERNS = [
    re.compile(r"\bhtml\.escape\s*\("),
    re.compile(r"\bmarkupsafe\.escape\s*\("),
    re.compile(r"\bbleach\.clean\s*\("),
]

# "Type cast sanitizer" per your rule: int(input()) => clean
CAST_CLEAN_CALL_PATTERNS = [
    re.compile(r"\bint\s*\("),
]


def _line_no(tok: tokenize.TokenInfo) -> int:
    return tok.start[0] - 1


def _col(tok: tokenize.TokenInfo) -> int:
    return tok.start[1]


def _is_name(tok: tokenize.TokenInfo) -> bool:
    return tok.type == tokenize.NAME


def _is_string(tok: tokenize.TokenInfo) -> bool:
    return tok.type == tokenize.STRING


def _join(tokens: List[tokenize.TokenInfo]) -> str:
    return "".join(t.string for t in tokens)


def _split_top_level_commas(tokens: List[tokenize.TokenInfo]) -> List[List[tokenize.TokenInfo]]:
    """
    Split token list by commas at top-level only (respect (),[],{} nesting).
    Used for tuple unpacking: x,y = input(), "safe"
    """
    parts: List[List[tokenize.TokenInfo]] = []
    cur: List[tokenize.TokenInfo] = []
    depth = 0
    for t in tokens:
        if t.type == tokenize.OP:
            if t.string in "([{":
                depth += 1
            elif t.string in ")]}":
                depth = max(0, depth - 1)
            elif t.string == "," and depth == 0:
                parts.append(cur)
                cur = []
                continue
        cur.append(t)
    parts.append(cur)
    return parts


def _extract_lhs_targets(left: List[tokenize.TokenInfo]) -> Tuple[List[str], Optional[Tuple[str, str]]]:
    """
    Extract assignment targets from LHS tokens.
    Returns:
      - list of variable names (for x=..., x,y=...)
      - optional dict-key target: (dictName, keyString) for d["k"] = ...
    Notes:
      - Very lightweight. For d["k"], only string-literal key is tracked.
    """
    # dict subscript pattern: NAME [ STRING ]
    # e.g., d["k"] = ...
    dict_key: Optional[Tuple[str, str]] = None
    # find first NAME then [ then STRING then ]
    # we'll scan linearly
    for i in range(len(left) - 3):
        if _is_name(left[i]) and left[i + 1].type == tokenize.OP and left[i + 1].string == "[" and _is_string(left[i + 2]) and left[i + 3].type == tokenize.OP and left[i + 3].string == "]":
            dict_name = left[i].string
            key_lit = left[i + 2].string
            # normalize string literal to raw content if possible (remove quotes)
            key = key_lit.strip()
            if len(key) >= 2 and key[0] in ("'", '"') and key[-1] == key[0]:
                key = key[1:-1]
            dict_key = (dict_name, key)
            break

    # tuple/unpack names: collect all NAME tokens on left (excluding keywords)
    names = [t.string for t in left if _is_name(t)]
    return names, dict_key


def _rhs_has_source(rhs_text: str) -> bool:
    return any(p.search(rhs_text) for p in SOURCE_CALL_PATTERNS)


def _rhs_has_sanitizer(rhs_text: str) -> bool:
    return any(p.search(rhs_text) for p in SANITIZER_CALL_PATTERNS)


def _rhs_has_cast_clean(rhs_text: str) -> bool:
    # int( ... ) is treated as clean per your rule, but only if its argument is tainted/source
    return any(p.search(rhs_text) for p in CAST_CLEAN_CALL_PATTERNS)


def _fstring_is_tainted(rhs_tokens: List[tokenize.TokenInfo], tainted_vars: Set[str]) -> bool:
    """
    Detect f-string taint:
      - RHS contains an f-string literal AND inside {} there is input()/request.* or tainted var name
    tokenize gives f-string as STRING token (e.g., 'f"hello {x}"').
    We'll do a simple substring check (case-based, not AST).
    """
    for t in rhs_tokens:
        if t.type == tokenize.STRING:
            s = t.string
            # f-string prefix can be like f"", F'', fr"", rf"", etc.
            # we'll check 'f' or 'F' in the prefix region before first quote.
            quote_pos = min([p for p in (s.find('"'), s.find("'")) if p != -1], default=-1)
            if quote_pos == -1:
                continue
            prefix = s[:quote_pos].lower()
            if "f" not in prefix:
                continue
            # if it has { ... }, check for source patterns or tainted vars names
            if "{" in s and "}" in s:
                # crude but effective for your goal
                if _rhs_has_source(s):
                    return True
                for v in tainted_vars:
                    if re.search(rf"\b{re.escape(v)}\b", s):
                        return True
    return False


def _rhs_uses_tainted(rhs_tokens: List[tokenize.TokenInfo], tainted_vars: Set[str], tainted_dict: Dict[str, Set[str]]) -> bool:
    """
    Determine whether RHS references tainted variables OR tainted dict keys.
    Handles:
      - y = x + "a"
      - x = d["k"]  (if d["k"] tainted tracked)
      - x = request.args.get(...) etc (source handled separately)
    """
    rhs_names = [t.string for t in rhs_tokens if _is_name(t)]
    if set(rhs_names) & tainted_vars:
        return True

    # dict read: NAME [ STRING ]
    for i in range(len(rhs_tokens) - 3):
        if _is_name(rhs_tokens[i]) and rhs_tokens[i + 1].type == tokenize.OP and rhs_tokens[i + 1].string == "[" and _is_string(rhs_tokens[i + 2]) and rhs_tokens[i + 3].type == tokenize.OP and rhs_tokens[i + 3].string == "]":
            dname = rhs_tokens[i].string
            key_lit = rhs_tokens[i + 2].string.strip()
            if len(key_lit) >= 2 and key_lit[0] in ("'", '"') and key_lit[-1] == key_lit[0]:
                key = key_lit[1:-1]
            else:
                key = key_lit
            if dname in tainted_dict and (key in tainted_dict[dname] or "*" in tainted_dict[dname]):
                return True

    # dict get: d.get("k")
    rhs_text = _join(rhs_tokens)
    m = re.search(r"\b([A-Za-z_]\w*)\.get\s*\(\s*(['\"])(.*?)\2", rhs_text)
    if m:
        dname = m.group(1)
        key = m.group(3)
        if dname in tainted_dict and (key in tainted_dict[dname] or "*" in tainted_dict[dname]):
            return True

    return False


def analyze(code: str) -> List[Issue]:
    """
    Case-based taint engine (Flask-focused) without AST.
    Applies your listed taint rules + sink detection.
    """
    issues: List[Issue] = []
    tainted_vars: Set[str] = set()
    sanitized_vars: Set[str] = set()
    tainted_dict: Dict[str, Set[str]] = {}  # d -> {"k", ...}  (tracked keys)

    try:
        toks = list(tokenize.generate_tokens(io.StringIO(code).readline))
    except tokenize.TokenError:
        # typing-in-progress breakage is normal; keep quiet
        return issues

    # Group tokens by line
    by_line: Dict[int, List[tokenize.TokenInfo]] = {}
    for t in toks:
        ln = _line_no(t)
        if ln < 0:
            continue
        by_line.setdefault(ln, []).append(t)

    for ln in sorted(by_line.keys()):
        ltoks = by_line[ln]
        line_text = _join(ltoks)
        stripped = line_text.strip()

        # ------------------------------------------------------------
        # Special case: try: x=input() except: x="safe" => x taint (your rule)
        # ------------------------------------------------------------
        if stripped.startswith("try:") and "except" in stripped and "=" in stripped:
            # If any assignment in try-part uses source => mark those LHS tainted
            # We'll be crude: if line has source anywhere, taint the first assigned variable.
            if _rhs_has_source(stripped):
                # take first NAME before '='
                eq_pos = None
                for i, t in enumerate(ltoks):
                    if t.type == tokenize.OP and t.string == "=":
                        eq_pos = i
                        break
                if eq_pos is not None:
                    left = ltoks[:eq_pos]
                    names, dict_key = _extract_lhs_targets(left)
                    if names:
                        tainted_vars.add(names[0])
                        sanitized_vars.discard(names[0])
                    if dict_key:
                        dname, key = dict_key
                        tainted_dict.setdefault(dname, set()).add(key)

        # ------------------------------------------------------------
        # Assignment handling (covers most of your cases)
        # ------------------------------------------------------------
        # Find first '=' (we treat per-line sequential; multi '=' handled by scanning)
        eq_positions = [i for i, t in enumerate(ltoks) if t.type == tokenize.OP and t.string == "="]
        if eq_positions:
            # Case: a = b = input()  (chain assignment)
            if len(eq_positions) >= 2:
                # We'll treat left targets as names before each '=' except the last rhs
                last_eq = eq_positions[-1]
                rhs_tokens = ltoks[last_eq + 1 :]
                rhs_text = _join(rhs_tokens)

                # collect LHS names across segments
                lhs_names: List[str] = []
                # e.g. tokens: a = b = input()
                # gather NAME tokens before last '='
                for t in ltoks[:last_eq]:
                    if _is_name(t):
                        lhs_names.append(t.string)

                # Apply your rule: if RHS is source => all lhs taint
                if _rhs_has_source(rhs_text) or _rhs_uses_tainted(rhs_tokens, tainted_vars, tainted_dict) or _fstring_is_tainted(rhs_tokens, tainted_vars):
                    for v in set(lhs_names):
                        tainted_vars.add(v)
                        sanitized_vars.discard(v)
                # If RHS sanitizer/cast-clean => all lhs clean
                elif _rhs_has_sanitizer(rhs_text) or _rhs_has_cast_clean(rhs_text):
                    for v in set(lhs_names):
                        sanitized_vars.add(v)
                        tainted_vars.discard(v)
                else:
                    # Otherwise: all lhs clean (overwrite semantics)
                    for v in set(lhs_names):
                        sanitized_vars.discard(v)
                        tainted_vars.discard(v)

            else:
                # Single assignment (including tuple unpack x,y = ...)
                eq_idx = eq_positions[0]
                left = ltoks[:eq_idx]
                right = ltoks[eq_idx + 1 :]

                lhs_names, dict_key = _extract_lhs_targets(left)
                rhs_text = _join(right)

                # Tuple unpack: x, y = <a>, <b>
                # We'll only use positional split if there is a comma on LHS
                lhs_has_comma = any(t.type == tokenize.OP and t.string == "," for t in left)
                if lhs_has_comma and lhs_names:
                    rhs_parts = _split_top_level_commas(right)
                    # Map each LHS var to corresponding RHS expr
                    for idx, v in enumerate(lhs_names):
                        part = rhs_parts[idx] if idx < len(rhs_parts) else []
                        part_text = _join(part)

                        # Apply rules
                        # Source => taint
                        if _rhs_has_source(part_text) or _fstring_is_tainted(part, tainted_vars):
                            tainted_vars.add(v)
                            sanitized_vars.discard(v)
                        # Sanitizer => clean
                        elif _rhs_has_sanitizer(part_text) or (_rhs_has_cast_clean(part_text) and (_rhs_has_source(part_text) or _rhs_uses_tainted(part, tainted_vars, tainted_dict))):
                            sanitized_vars.add(v)
                            tainted_vars.discard(v)
                        # Propagation => taint
                        elif _rhs_uses_tainted(part, tainted_vars, tainted_dict):
                            tainted_vars.add(v)
                            sanitized_vars.discard(v)
                        else:
                            # overwrite => clean
                            tainted_vars.discard(v)
                            sanitized_vars.discard(v)

                else:
                    # Normal x = <expr> or d["k"] = <expr> or x = <ternary>
                    # Your rule: x = input() if cond else "safe" => x taint (even if else safe)
                    is_ternary_with_source = (" if " in rhs_text and " else " in rhs_text and _rhs_has_source(rhs_text))

                    rhs_is_source = _rhs_has_source(rhs_text)
                    rhs_is_sanitizer = _rhs_has_sanitizer(rhs_text)
                    rhs_is_cast_clean = _rhs_has_cast_clean(rhs_text) and (rhs_is_source or _rhs_uses_tainted(right, tainted_vars, tainted_dict))
                    rhs_is_fstring_taint = _fstring_is_tainted(right, tainted_vars)
                    rhs_uses_taint = _rhs_uses_tainted(right, tainted_vars, tainted_dict)

                    # dict-key assignment tracking
                    if dict_key:
                        dname, key = dict_key
                        if rhs_is_source or rhs_is_fstring_taint or rhs_uses_taint or is_ternary_with_source:
                            tainted_dict.setdefault(dname, set()).add(key)
                        elif rhs_is_sanitizer or rhs_is_cast_clean:
                            # mark that specific key clean by removing it
                            if dname in tainted_dict and key in tainted_dict[dname]:
                                tainted_dict[dname].discard(key)
                                if not tainted_dict[dname]:
                                    tainted_dict.pop(dname, None)
                        else:
                            # overwrite to clean (remove tracked key)
                            if dname in tainted_dict and key in tainted_dict[dname]:
                                tainted_dict[dname].discard(key)
                                if not tainted_dict[dname]:
                                    tainted_dict.pop(dname, None)

                    # variable assignment
                    if lhs_names:
                        # We treat only the first LHS var for simple "x = ..."
                        v = lhs_names[0]

                        # SOURCE or ternary-source => taint
                        if rhs_is_source or rhs_is_fstring_taint or is_ternary_with_source:
                            tainted_vars.add(v)
                            sanitized_vars.discard(v)

                        # SANITIZER => clean
                        elif rhs_is_sanitizer:
                            sanitized_vars.add(v)
                            tainted_vars.discard(v)

                        # CAST CLEAN => clean (int(...) rule)
                        elif rhs_is_cast_clean:
                            sanitized_vars.add(v)
                            tainted_vars.discard(v)

                        # PROPAGATION => taint
                        elif rhs_uses_taint:
                            tainted_vars.add(v)
                            sanitized_vars.discard(v)

                        else:
                            # overwrite semantics: x = "safe" => clean
                            tainted_vars.discard(v)
                            sanitized_vars.discard(v)

        # ------------------------------------------------------------
        # Sink checks
        # ------------------------------------------------------------
        # return sink
        if stripped.startswith("return"):
            used_names = {t.string for t in ltoks if _is_name(t)}
            used_tainted = (used_names & tainted_vars) - sanitized_vars

            # also catch return d["k"] if tracked
            rhs_tokens = ltoks
            if _rhs_uses_tainted(rhs_tokens, set(), tainted_dict):  # variable set empty; dict only
                used_tainted = set(used_tainted) | {"<dict-taint>"}

            if used_tainted:
                ret_tok = next((t for t in ltoks if t.string == "return"), ltoks[0])
                issues.append(Issue(
                    line=ln,
                    col=_col(ret_tok),
                    end_col=_col(ret_tok) + len("return"),
                    severity=1,
                    message=f"Possible XSS (case-based, Flask): returning tainted value {sorted(used_tainted)} without sanitizer."
                ))

        # function sink
        if any(p.search(line_text) for p in SINK_CALL_PATTERNS):
            used_names = {t.string for t in ltoks if _is_name(t)}
            used_tainted = (used_names & tainted_vars) - sanitized_vars

            # dict taint in args
            if _rhs_uses_tainted(ltoks, set(), tainted_dict):
                used_tainted = set(used_tainted) | {"<dict-taint>"}

            if used_tainted:
                fn_tok = next((t for t in ltoks if _is_name(t)), ltoks[0])
                issues.append(Issue(
                    line=ln,
                    col=_col(fn_tok),
                    end_col=_col(fn_tok) + len(fn_tok.string),
                    severity=1,
                    message=f"Possible XSS (case-based, Flask): sink receives tainted value {sorted(used_tainted)} without sanitizer."
                ))

    return issues
