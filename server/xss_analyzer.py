import io
import re
import tokenize
from dataclasses import dataclass
from typing import Dict, List, Set


@dataclass
class Issue:
    line: int      # 0-based
    col: int       # 0-based
    end_col: int   # 0-based
    message: str
    severity: int  # 1=Error, 2=Warning


# -----------------------
# Flask case library
# -----------------------

# Source: Flask 외부 입력 케이스
SOURCE_CALL_PATTERNS = [
    re.compile(r"request\.(args|form|values)\.get\s*\("),
    re.compile(r"request\.(args|form|values)\s*\["),  # request.args["q"] 같은 인덱싱
    re.compile(r"request\.get_json\s*\("),
    re.compile(r"request\.json\b"),                   # request.json
]

# Sink: raw HTML 응답으로 이어질 가능성이 큰 케이스
SINK_CALL_PATTERNS = [
    re.compile(r"render_template_string\s*\("),
    re.compile(r"Response\s*\("),
    re.compile(r"make_response\s*\("),
    re.compile(r"Markup\s*\("),  # Markup은 "안전"으로 오해하기 쉬워서, tainted 들어가면 경고
]

# Sanitizer: escape/clean 케이스
SANITIZER_CALL_PATTERNS = [
    re.compile(r"html\.escape\s*\("),
    re.compile(r"markupsafe\.escape\s*\("),
    re.compile(r"bleach\.clean\s*\("),
]


def _line_no(tok: tokenize.TokenInfo) -> int:
    return tok.start[0] - 1


def _col(tok: tokenize.TokenInfo) -> int:
    return tok.start[1]


def _is_name(tok: tokenize.TokenInfo) -> bool:
    return tok.type == tokenize.NAME


def _join(tokens: List[tokenize.TokenInfo]) -> str:
    # 토큰들을 공백 없이 붙여서 "라인 표현"으로 사용 (케이스 매칭용)
    return "".join(t.string for t in tokens)


def analyze(code: str) -> List[Issue]:
    """
    AST 없이 tokenize 기반으로:
    - 케이스 기반(Source/Sink/Sanitizer) 판정
    - 초경량 taint 전파 (x=..., y=x 정도)
    - return/sink에서 tainted가 나가면 경고
    """
    issues: List[Issue] = []
    tainted: Set[str] = set()
    sanitized: Set[str] = set()

    try:
        toks = list(tokenize.generate_tokens(io.StringIO(code).readline))
    except tokenize.TokenError:
        # 타이핑 중 문법이 잠깐 깨지는 건 흔하니 조용히 무시
        return issues

    # 라인별 토큰 모으기
    by_line: Dict[int, List[tokenize.TokenInfo]] = {}
    for t in toks:
        ln = _line_no(t)
        if ln < 0:
            continue
        by_line.setdefault(ln, []).append(t)

    for ln, ltoks in by_line.items():
        line_text = _join(ltoks)
        stripped = line_text.strip()

        # --------------------------
        # (1) 대입문: x = <expr>
        # --------------------------
        eq_idx = None
        for i, t in enumerate(ltoks):
            if t.type == tokenize.OP and t.string == "=":
                eq_idx = i
                break

        if eq_idx is not None:
            left = ltoks[:eq_idx]
            right = ltoks[eq_idx + 1 :]

            # 매우 원초적으로: 좌변에서 첫 변수명만 추출 (x = ...)
            left_names = [t.string for t in left if _is_name(t)]
            if left_names:
                var = left_names[0]
                rhs = _join(right)

                # Source 케이스
                if any(p.search(rhs) for p in SOURCE_CALL_PATTERNS):
                    tainted.add(var)
                    sanitized.discard(var)

                # Sanitizer 케이스
                elif any(p.search(rhs) for p in SANITIZER_CALL_PATTERNS):
                    sanitized.add(var)
                    tainted.discard(var)

                else:
                    # 전파: RHS에 tainted 변수가 포함되면 var도 tainted
                    rhs_names = {t.string for t in right if _is_name(t)}
                    if (rhs_names & tainted) and (var not in sanitized):
                        tainted.add(var)

        # --------------------------
        # (2) return <expr> = sink 케이스
        # --------------------------
        if stripped.startswith("return"):
            used_names = {t.string for t in ltoks if _is_name(t)}
            used_tainted = (used_names & tainted) - sanitized
            if used_tainted:
                # return 키워드 위치에 밑줄
                ret_tok = next((t for t in ltoks if t.string == "return"), ltoks[0])
                issues.append(Issue(
                    line=ln,
                    col=_col(ret_tok),
                    end_col=_col(ret_tok) + len("return"),
                    severity=1,
                    message=f"Possible XSS (case-based, Flask): returning tainted value {sorted(used_tainted)} without sanitizer."
                ))

        # --------------------------
        # (3) Sink 함수 호출 케이스
        # --------------------------
        if any(p.search(line_text) for p in SINK_CALL_PATTERNS):
            used_names = {t.string for t in ltoks if _is_name(t)}
            used_tainted = (used_names & tainted) - sanitized
            if used_tainted:
                # 함수명 토큰에 밑줄
                fn_tok = next((t for t in ltoks if _is_name(t)), ltoks[0])
                issues.append(Issue(
                    line=ln,
                    col=_col(fn_tok),
                    end_col=_col(fn_tok) + len(fn_tok.string),
                    severity=1,
                    message=f"Possible XSS (case-based, Flask): sink receives tainted value {sorted(used_tainted)} without sanitizer."
                ))

    return issues
