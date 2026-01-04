import ast
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Issue:
    line: int          # 0-based
    col: int           # 0-based
    end_col: int       # 0-based
    message: str
    severity: int      # 1=Error, 2=Warning


def _is_html_like(s: str) -> bool:
    # 초간단 휴리스틱: 태그처럼 보이면 HTML 컨텍스트로 간주
    return ("<" in s and ">" in s)


def _const_str(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _contains_var(node: ast.AST) -> bool:
    # "외부 입력"을 진짜 추적(taint)하지는 않고, 단순히 변수/속성/인덱스가 섞이면 위험 후보로 봄
    for n in ast.walk(node):
        if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript)):
            return True
    return False


def _contains_html_literal(node: ast.AST) -> bool:
    for n in ast.walk(node):
        s = _const_str(n)
        if s is not None and _is_html_like(s):
            return True
    return False


def _call_name(node: ast.Call) -> str:
    # render_template_string(...) 같은 함수 이름 추출
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


class Analyzer(ast.NodeVisitor):
    """
    목표: "HTML 컨텍스트로 보이는 문자열 + 변수 결합"을 XSS 의심으로 진단
    (데모/간단 LSP용 룰)
    """
    def __init__(self):
        self.issues: List[Issue] = []

    def visit_Return(self, node: ast.Return):
        # return f"<div>{user}</div>"
        if node.value and self._looks_like_xss_expr(node.value):
            self._emit(node, "Possible XSS: HTML is returned with interpolated variable (consider escaping/sanitizing).", severity=1)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # render_template_string(user_input) 같은 위험 API
        fn = _call_name(node)
        risky = {"render_template_string", "Markup", "mark_safe", "safe"}  # 극단적으로 간단한 룰(확장 가능)
        if fn in risky and node.args:
            if _contains_var(node.args[0]):
                self._emit(node, f"Possible XSS: call to `{fn}` with variable input (consider escaping/sanitizing).", severity=1)
        self.generic_visit(node)

    def _looks_like_xss_expr(self, expr: ast.AST) -> bool:
        # f-string(JoinedStr): HTML literal + 변수 포함
        if isinstance(expr, ast.JoinedStr):
            return _contains_html_literal(expr) and _contains_var(expr)

        # "a" + user / user + "<div>"
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return (_contains_html_literal(expr) and _contains_var(expr))

        # "<div>{}</div>".format(user)
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
            if expr.func.attr == "format" and _contains_html_literal(expr.func.value):
                return bool(expr.args) and _contains_var(expr)

        return False

    def _emit(self, node: ast.AST, message: str, severity: int):
        lineno = getattr(node, "lineno", 1) - 1
        col = getattr(node, "col_offset", 0)
        end_col = getattr(node, "end_col_offset", col + 1)
        self.issues.append(Issue(lineno, col, end_col, message, severity))


def analyze(code: str) -> List[Issue]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        # 타이핑 중 깨진 코드는 조용히 무시(실시간 경험 중요)
        return []
    a = Analyzer()
    a.visit(tree)
    return a.issues
