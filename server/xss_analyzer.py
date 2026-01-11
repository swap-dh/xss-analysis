import ast
from dataclasses import dataclass
from typing import DefaultDict, Iterable, List, Optional, Set, Tuple


@dataclass
class Issue:
    line: int      # 0-based
    col: int       # 0-based
    end_col: int   # 0-based
    message: str
    severity: int  # 1=Error, 2=Warning


@dataclass
class TaintResult:
    tainted: bool = False
    sanitized: bool = False
    sources: Set[str] = None

    def __post_init__(self) -> None:
        if self.sources is None:
            self.sources = set()


KNOWN_SANITIZERS = {
    "html.escape",
    "markupsafe.escape",
    "bleach.clean",
    "django.utils.html.escape",
    "django.utils.html.format_html",
    "flask.escape",
}

# int(...) is treated as a sanitizer per requirements
CAST_CLEAN_FUNCS = {"int"}

SINK_CALLS = {
    "render_template",
    "render_template_string",
    "flask.render_template",
    "flask.render_template_string",
    "Response",
    "flask.Response",
    "make_response",
    "flask.make_response",
    "Markup",
    "markupsafe.Markup",
    "render",
    "django.shortcuts.render",
    "HttpResponse",
    "django.http.HttpResponse",
    "HttpResponseBadRequest",
    "HttpResponseNotFound",
    "HttpResponseForbidden",
    "HttpResponseRedirect",
    "TemplateResponse",
    "Jinja2Templates.TemplateResponse",
    "templates.TemplateResponse",
    "HTMLResponse",
    "fastapi.responses.HTMLResponse",
    "PlainTextResponse",
    "fastapi.responses.PlainTextResponse",
}

SAFE_JSON_RESPONSES = {
    "jsonify",
    "flask.jsonify",
    "JSONResponse",
    "fastapi.responses.JSONResponse",
    "ORJSONResponse",
    "fastapi.responses.ORJSONResponse",
    "UJSONResponse",
    "fastapi.responses.UJSONResponse",
}


def analyze(code: str) -> List[Issue]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    user_sanitizers = _discover_user_sanitizers(tree)
    analyzer = TaintAnalyzer(code, user_sanitizers, tree)
    analyzer.visit(tree)
    return analyzer.issues


def _discover_user_sanitizers(tree: ast.AST) -> Set[str]:
    """
    Detect user-defined sanitizers by looking for functions that return a known sanitizer
    or cast-clean output. This lets us treat sanitize(...) as safe only when it actually
    escapes or normalizes input.
    """
    sanitizers: Set[str] = set()

    def is_sanitizing_expr(expr: ast.AST) -> bool:
        if isinstance(expr, ast.Call):
            name = _call_name(expr.func)
            if name in KNOWN_SANITIZERS or (isinstance(expr.func, ast.Name) and expr.func.id in CAST_CLEAN_FUNCS):
                return True
        if isinstance(expr, ast.Name) and expr.id in sanitizers:
            return True
        return False

    class Finder(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            for stmt in node.body:
                if isinstance(stmt, ast.Return) and is_sanitizing_expr(stmt.value):
                    sanitizers.add(node.name)
                    break

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(node)  # type: ignore[arg-type]

    Finder().visit(tree)
    return sanitizers


def _call_name(func: ast.AST) -> str:
    """
    Convert an ast.Name/ast.Attribute into dotted name: request.args.get -> "request.args.get"
    """
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: List[str] = []
        cur: Optional[ast.AST] = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    return ""


def _literal_key(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
        return str(node.value)
    if isinstance(node, ast.Str):
        return node.s
    return None


def _merge(results: Iterable[TaintResult]) -> TaintResult:
    tainted_sources: Set[str] = set()
    sanitized = False
    tainted = False
    for res in results:
        if res.tainted:
            tainted = True
            tainted_sources |= res.sources
        sanitized = sanitized or res.sanitized
    if tainted:
        sanitized = False
    return TaintResult(tainted=tainted, sanitized=sanitized, sources=tainted_sources)


def _collect_function_defs(tree: ast.AST) -> Set[str]:
    names: Set[str] = set()

    class Collector(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            names.add(node.name)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            names.add(node.name)
            self.generic_visit(node)

    Collector().visit(tree)
    return names


class TaintAnalyzer(ast.NodeVisitor):
    def __init__(self, code: str, user_sanitizers: Set[str], tree: ast.AST) -> None:
        self.code = code
        self.issues: List[Issue] = []
        self.tainted: Set[str] = set()
        self.sanitized: Set[str] = set()
        self.tainted_dict: DefaultDict[str, Set[str]] = DefaultDict(set)
        self.attr_tainted: DefaultDict[str, Set[str]] = DefaultDict(set)
        self.sanitizer_funcs: Set[str] = set(KNOWN_SANITIZERS) | set(user_sanitizers)
        self.function_defs: Set[str] = _collect_function_defs(tree)

    # ---------- visitors ----------
    def visit_Module(self, node: ast.Module) -> None:
        for stmt in node.body:
            self.visit(stmt)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for stmt in node.body:
            self.visit(stmt)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_like(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_like(node)

    def _visit_function_like(self, node: ast.AST) -> None:
        saved_tainted = self.tainted
        saved_sanitized = self.sanitized
        saved_dict = self.tainted_dict

        self.tainted = set()
        self.sanitized = set()
        self.tainted_dict = DefaultDict(set)

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if self._decorators_imply_endpoint(node.decorator_list):
                for arg in node.args.args:
                    if arg.arg not in {"self", "cls", "request"}:
                        self.tainted.add(arg.arg)

        for stmt in getattr(node, "body", []):
            self.visit(stmt)

        self.tainted = saved_tainted
        self.sanitized = saved_sanitized
        self.tainted_dict = saved_dict

    def visit_Assign(self, node: ast.Assign) -> None:
        value_res = self.expr_taint(node.value)

        if len(node.targets) > 1:
            for target in node.targets:
                self._assign_target(target, value_res)
        else:
            self._assign_target(node.targets[0], value_res, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        value_res = self.expr_taint(node.value) if node.value is not None else TaintResult()
        self._assign_target(node.target, value_res, node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        target_res = self.expr_taint(node.target)
        value_res = self.expr_taint(node.value)
        combined = _merge([target_res, value_res])
        self._assign_target(node.target, combined)

    def visit_Return(self, node: ast.Return) -> None:
        res = self.expr_taint(node.value)
        if res.tainted and not res.sanitized:
            html_context = self._expression_contains_html(node.value)
            label = "HTML" if html_context else "value"
            msg = f"Possible XSS: returning tainted {label}"
            if res.sources:
                msg += f" (sources: {sorted(res.sources)})"
            self._add_issue(node, msg)

    def visit_Expr(self, node: ast.Expr) -> None:
        self.expr_taint(node.value)

    def visit_Try(self, node: ast.Try) -> None:
        before_tainted = set(self.tainted)
        for stmt in node.body:
            self.visit(stmt)
        sticky = self.tainted - before_tainted
        for handler in node.handlers:
            self.visit(handler)
            if sticky:
                self.tainted.update(sticky)
                for name in sticky:
                    self.sanitized.discard(name)
        for stmt in node.orelse:
            self.visit(stmt)
        for stmt in node.finalbody:
            self.visit(stmt)

    # ---------- helpers ----------
    def _assign_target(self, target: ast.AST, value_res: TaintResult, value_node: Optional[ast.AST] = None) -> None:
        if isinstance(target, ast.Name):
            was_tainted = target.id in self.tainted
            if value_res.tainted:
                self._mark_tainted(target.id, value_res.sources)
            elif value_res.sanitized:
                self._mark_sanitized(target.id)
            else:
                # If assigning a function-like name to a previously tainted var, keep taint (likely not sanitizer)
                if was_tainted and isinstance(value_node, ast.Name) and value_node.id not in self.sanitizer_funcs:
                    return
                self._clear_var(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value_node, (ast.Tuple, ast.List)):
                pairs = zip(target.elts, value_node.elts)
                for tgt, expr in pairs:
                    self._assign_target(tgt, self.expr_taint(expr), expr)
            else:
                for tgt in target.elts:
                    self._assign_target(tgt, value_res, value_node)
        elif isinstance(target, ast.Subscript):
            base_name = target.value.id if isinstance(target.value, ast.Name) else None
            key = _literal_key(getattr(target, "slice", None))
            if value_res.tainted and base_name and key is not None:
                self.tainted_dict[base_name].add(key)
            elif base_name and key is not None:
                if key in self.tainted_dict.get(base_name, set()):
                    self.tainted_dict[base_name].discard(key)
                    if not self.tainted_dict[base_name]:
                        self.tainted_dict.pop(base_name, None)
        elif isinstance(target, ast.Attribute):
            base_name = target.value.id if isinstance(target.value, ast.Name) else None
            attr = target.attr if isinstance(target, ast.Attribute) else None
            if base_name and attr:
                if value_res.tainted:
                    self.attr_tainted[base_name].add(attr)
                elif value_res.sanitized:
                    if attr in self.attr_tainted.get(base_name, set()):
                        self.attr_tainted[base_name].discard(attr)
                        if not self.attr_tainted[base_name]:
                            self.attr_tainted.pop(base_name, None)
                else:
                    if attr in self.attr_tainted.get(base_name, set()):
                        self.attr_tainted[base_name].discard(attr)
                        if not self.attr_tainted[base_name]:
                            self.attr_tainted.pop(base_name, None)
        else:
            if value_res.tainted and isinstance(target, ast.Attribute):
                name = _call_name(target)
                self._mark_tainted(name or "<attr>", value_res.sources)

    def _mark_tainted(self, name: str, sources: Set[str]) -> None:
        self.tainted.add(name)
        self.sanitized.discard(name)

    def _mark_sanitized(self, name: str) -> None:
        self.tainted.discard(name)
        self.sanitized.add(name)

    def _clear_var(self, name: str) -> None:
        self.tainted.discard(name)
        self.sanitized.discard(name)

    def expr_taint(self, node: Optional[ast.AST]) -> TaintResult:
        if node is None:
            return TaintResult()

        if isinstance(node, ast.Constant):
            return TaintResult()

        if isinstance(node, ast.Name):
            if node.id in self.tainted:
                return TaintResult(tainted=True, sources={node.id})
            if node.id in self.sanitized:
                return TaintResult(sanitized=True)
            return TaintResult()

        if isinstance(node, ast.Attribute):
            chain = _call_name(node)
            if self._attribute_is_request_source(chain):
                return TaintResult(tainted=True, sources={chain})
            base_name = node.value.id if isinstance(node.value, ast.Name) else None
            if base_name and node.attr in self.attr_tainted.get(base_name, set()):
                return TaintResult(tainted=True, sources={f"{base_name}.{node.attr}"})
            base_res = self.expr_taint(node.value)
            if base_res.tainted:
                return TaintResult(tainted=True, sources=base_res.sources or {chain})
            if base_res.sanitized:
                return TaintResult(sanitized=True)
            return TaintResult()

        if isinstance(node, ast.Subscript):
            if self._subscript_is_request_source(node):
                return TaintResult(tainted=True, sources={"request"})
            base_res = self.expr_taint(node.value)
            key = _literal_key(getattr(node, "slice", None))
            base_name = node.value.id if isinstance(node.value, ast.Name) else None
            tainted = False
            sources: Set[str] = set()
            if base_res.tainted:
                tainted = True
                sources |= base_res.sources
            elif base_name and key is not None:
                if key in self.tainted_dict.get(base_name, set()) or "*" in self.tainted_dict.get(base_name, set()):
                    tainted = True
                    sources.add(f"{base_name}[{key}]")
            sanitized = False
            if not tainted and base_res.sanitized:
                sanitized = True
            return TaintResult(tainted=tainted, sanitized=sanitized, sources=sources)

        if isinstance(node, ast.Call):
            return self._taint_from_call(node)

        if isinstance(node, ast.JoinedStr):
            parts = [self.expr_taint(v) for v in node.values]
            return _merge(parts)

        if isinstance(node, ast.FormattedValue):
            return self.expr_taint(node.value)

        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            left = self.expr_taint(node.left)
            right = self.expr_taint(node.right)
            return _merge([left, right])

        if isinstance(node, ast.BoolOp):
            return _merge(self.expr_taint(v) for v in node.values)

        if isinstance(node, ast.Compare):
            parts = [self.expr_taint(node.left)] + [self.expr_taint(c) for c in node.comparators]
            return _merge(parts)

        if isinstance(node, ast.IfExp):
            body_res = self.expr_taint(node.body)
            else_res = self.expr_taint(node.orelse)
            tainted = body_res.tainted or else_res.tainted
            sanitized = (body_res.sanitized and else_res.sanitized) and not tainted
            sources = set()
            if body_res.tainted:
                sources |= body_res.sources
            if else_res.tainted:
                sources |= else_res.sources
            return TaintResult(tainted=tainted, sanitized=sanitized, sources=sources)

        if isinstance(node, ast.Dict):
            vals = [self.expr_taint(v) for v in node.values]
            return _merge(vals)

        return TaintResult()

    def _taint_from_call(self, node: ast.Call) -> TaintResult:
        name = _call_name(node.func)
        arg_results = [self.expr_taint(a) for a in node.args] + [self.expr_taint(k.value) for k in node.keywords]
        self._check_sink_call(node, name, arg_results)

        if self._is_source_call(name):
            src = name or "external-input"
            return TaintResult(tainted=True, sources={src})

        if name in SAFE_JSON_RESPONSES:
            return TaintResult(sanitized=True)

        if name in self.sanitizer_funcs:
            return TaintResult(sanitized=True)

        if isinstance(node.func, ast.Name) and node.func.id in CAST_CLEAN_FUNCS:
            tainted_args = any(r.tainted for r in arg_results)
            if tainted_args:
                return TaintResult(sanitized=True)
            return TaintResult()

        tainted_sources: Set[str] = set()
        for res in arg_results:
            if res.tainted:
                tainted_sources |= res.sources
        tainted = bool(tainted_sources)
        sanitized = not tainted and any(r.sanitized for r in arg_results)

        # str.format / format_map on HTML-ish templates
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "format_map"}:
            if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                if "<" in node.func.value.value and ">" in node.func.value.value:
                    tainted = tainted or bool(tainted_sources)
                    sanitized = False

        return TaintResult(tainted=tainted, sanitized=sanitized, sources=tainted_sources)

    def _is_source_call(self, name: str) -> bool:
        if name == "input":
            return True
        lower = name.lower()
        request_prefixes = [
            "request.args",
            "request.form",
            "request.values",
            "request.get_json",
            "request.json",
            "request.data",
            "request.get_data",
            "request.body",
            "request.stream",
            "request.headers",
            "request.cookies",
            "request.cookies.get",
            "request.cookies.__getitem__",
            "request.GET",
            "request.POST",
            "request.COOKIES",
            "request.META",
            "request.query_params",
            "request.path_params",
        ]
        if any(lower.startswith(pref.lower()) for pref in request_prefixes):
            return True
        if ".request." in lower:
            for suffix in ("args", "form", "values", "get_json", "json", "headers", "cookies", "meta", "get"):
                if suffix in lower:
                    return True
        return False

    def _attribute_is_request_source(self, chain: str) -> bool:
        lower = chain.lower()
        attr_hits = [
            "request.args",
            "request.form",
            "request.values",
            "request.json",
            "request.data",
            "request.body",
            "request.headers",
            "request.cookies",
            "request.get",
            "request.get_data",
            "request.meta",
            "request.query_params",
            "request.path_params",
            "request.GET",
            "request.POST",
            "request.COOKIES",
            "request.META",
        ]
        if any(lower.startswith(a.lower()) for a in attr_hits):
            return True
        if ".request." in lower:
            return True
        return False

    def _subscript_is_request_source(self, node: ast.Subscript) -> bool:
        if isinstance(node.value, ast.Attribute):
            chain = _call_name(node.value)
            return self._attribute_is_request_source(chain)
        if isinstance(node.value, ast.Name) and node.value.id == "request":
            return True
        return False

    def _check_sink_call(self, node: ast.Call, name: str, arg_results: List[TaintResult]) -> None:
        tainted_args = [res for res in arg_results if res.tainted and not res.sanitized]
        if not tainted_args:
            return
        lower_name = name.lower()
        is_response_like = lower_name.endswith("response") or lower_name.endswith("render") or name in SINK_CALLS
        if name in SAFE_JSON_RESPONSES:
            return
        if not is_response_like and name not in SINK_CALLS:
            return
        sources: Set[str] = set()
        for res in tainted_args:
            sources |= res.sources
        msg = f"Possible XSS: tainted data flows into sink '{name or '<call>'}'"
        if sources:
            msg += f" (sources: {sorted(sources)})"
        self._add_issue(node, msg)

    def _expression_contains_html(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return "<" in node.value and ">" in node.value
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str) and "<" in part.value and ">" in part.value:
                    return True
                if isinstance(part, ast.FormattedValue):
                    if self._expression_contains_html(part.value):
                        return True
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._expression_contains_html(node.left) or self._expression_contains_html(node.right)
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in {"Markup", "markupsafe.Markup", "HTMLResponse", "fastapi.responses.HTMLResponse", "render_template_string"}:
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "format_map"}:
                if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                    if "<" in node.func.value.value and ">" in node.func.value.value:
                        return True
        return False

    def _decorators_imply_endpoint(self, decorators: List[ast.expr]) -> bool:
        for dec in decorators:
            name = _call_name(dec) if not isinstance(dec, ast.Call) else _call_name(dec.func)
            lower = name.lower()
            endpoint_markers = ("route", "get", "post", "put", "delete", "patch", "options", "api_view")
            if any(lower.endswith(m) or lower.endswith(f".{m}") for m in endpoint_markers):
                return True
        return False

    def _add_issue(self, node: ast.AST, message: str) -> None:
        line, col, end_col = self._span(node)
        self.issues.append(Issue(
            line=line,
            col=col,
            end_col=end_col,
            severity=1,
            message=message,
        ))

    def _span(self, node: ast.AST) -> Tuple[int, int, int]:
        line = max(0, getattr(node, "lineno", 1) - 1)
        col = max(0, getattr(node, "col_offset", 0))
        end_col = getattr(node, "end_col_offset", col + 1)
        if end_col is None:
            end_col = col + 1
        return line, col, end_col
