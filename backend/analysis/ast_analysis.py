"""Simple AST-based vulnerability analyzer for demonstration.

Detects:
- Source-to-sink flows where tainted input (input(), sys.argv, os.environ) reaches dangerous sinks
  such as eval/exec or subprocess/os.system.
- Direct use of eval/exec
- Unsafe file writes (open(..., mode) with 'w' or 'a')

Returns counts, detailed findings, and a primitive risk score.
"""
import ast
from typing import Any, Dict, List, Tuple

# types for readability
Finding = Dict[str, Any]


class _SourceVisitor(ast.NodeVisitor):
    """Collects tainted variable names and keeps track of source expressions."""

    def __init__(self, code: str):
        self.code = code
        self.tainted_vars = set()  # variable names that are tainted
        # record direct source expressions in case they are passed directly to sinks
        self.sources: List[Tuple[int, str]] = []

    def visit_Assign(self, node: ast.Assign):
        # if right side is a source, mark left-hand names as tainted
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
            if node.value.func.id == "input":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
        elif isinstance(node.value, ast.Subscript):
            if _is_sys_argv(node.value) or _is_os_environ(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # raw call to input() counts as a source expression
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            self.sources.append((node.lineno, _get_source_segment(self.code, node)))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        if _is_sys_argv(node) or _is_os_environ(node):
            self.sources.append((node.lineno, _get_source_segment(self.code, node)))
        self.generic_visit(node)


class _SinkVisitor(ast.NodeVisitor):
    """Collects sink usages and matches tainted data to sinks."""

    def __init__(self, code: str, tainted_vars: set, source_exprs: List[Tuple[int, str]]):
        self.code = code
        self.tainted_vars = tainted_vars
        self.source_exprs = source_exprs

        self.flows: List[Finding] = []
        self.eval_exec_calls: List[Finding] = []
        self.unsafe_writes: List[Finding] = []

    def visit_Call(self, node: ast.Call):
        fname = _get_full_call_name(node)
        # record eval/exec calls always
        if fname in ("eval", "exec"):
            self.eval_exec_calls.append(_make_finding(node, "eval_exec", fname))
            # check if argument is tainted/right from source
            for arg in node.args:
                if _expr_is_tainted(arg, self.tainted_vars) or _expr_is_source(arg, self.source_exprs):
                    self.flows.append(_make_flow(self.code, node, arg, fname))
        # detect os.system or subprocess...
        if fname in ("os.system", "subprocess.call", "subprocess.Popen", "subprocess.run"):
            for arg in node.args:
                if _expr_is_tainted(arg, self.tainted_vars) or _expr_is_source(arg, self.source_exprs):
                    self.flows.append(_make_flow(self.code, node, arg, fname))
        # open with write mode
        if fname == "open":
            mode = None
            if len(node.args) >= 2:
                m = node.args[1]
                if isinstance(m, ast.Constant) and isinstance(m.value, str):
                    mode = m.value
            elif any(kw.arg == "mode" for kw in node.keywords):
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = kw.value.value
            if mode and any(c in mode for c in ("w", "a")):
                self.unsafe_writes.append(_make_finding(node, "unsafe_write", mode))
        self.generic_visit(node)


def analyze_code(code: str, filename: str = "<string>") -> Dict[str, Any]:
    """Analyze a single file of Python source code and return structured findings."""
    try:
        tree = ast.parse(code, filename=filename)
    except SyntaxError:
        # skip files with parse errors
        return {}

    source_vis = _SourceVisitor(code)
    source_vis.visit(tree)

    sink_vis = _SinkVisitor(code, source_vis.tainted_vars, source_vis.sources)
    sink_vis.visit(tree)

    counts = {
        "tainted_flows": len(sink_vis.flows),
        "eval_exec": len(sink_vis.eval_exec_calls),
        "unsafe_writes": len(sink_vis.unsafe_writes),
    }
    # simple risk formula: weighted sum
    risk = counts["tainted_flows"] * 5 + counts["eval_exec"] * 3 + counts["unsafe_writes"] * 2

    return {
        "file": filename,
        "counts": counts,
        "risk": risk,
        "flows": sink_vis.flows,
        "eval_exec_calls": sink_vis.eval_exec_calls,
        "unsafe_writes": sink_vis.unsafe_writes,
    }


def analyze_files(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Given a list of file dicts (each must have 'path' and 'content'), analyze all and merge results."""
    total = {"tainted_flows": 0, "eval_exec": 0, "unsafe_writes": 0}
    findings = {"tainted_flows": [], "eval_exec": [], "unsafe_writes": []}
    risk_score = 0
    file_results = []

    for f in files:
        code = f.get("content")
        if not code:
            continue
        res = analyze_code(code, filename=f.get("path", "<string>"))
        if not res:
            continue
        file_results.append(res)
        # accumulate totals
        total["tainted_flows"] += res["counts"].get("tainted_flows", 0)
        total["eval_exec"] += res["counts"].get("eval_exec", 0)
        total["unsafe_writes"] += res["counts"].get("unsafe_writes", 0)
        # merge individual findings lists
        findings["tainted_flows"].extend(res.get("flows", []))
        findings["eval_exec"].extend(res.get("eval_exec_calls", []))
        findings["unsafe_writes"].extend(res.get("unsafe_writes", []))
        risk_score += res["risk"]

    return {
        "files_analyzed": len(file_results),
        "counts": total,
        "risk_score": risk_score,
        "files": file_results,
        "findings": findings,
    }


# helpers -------------------------------------------------------

def _get_source_segment(code: str, node: ast.AST) -> str:
    try:
        return ast.get_source_segment(code, node) or ""
    except Exception:
        return ""


def _get_full_call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        # potentially nested like subprocess.run
        parts = []
        curr = node.func
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return ".".join(reversed(parts))
    return ""


def _expr_is_tainted(expr: ast.AST, tainted_vars: set) -> bool:
    if isinstance(expr, ast.Name) and expr.id in tainted_vars:
        return True
    # handle simple binary operations where one side is tainted
    for child in ast.walk(expr):
        if isinstance(child, ast.Name) and child.id in tainted_vars:
            return True
    return False


def _expr_is_source(expr: ast.AST, sources: List[Tuple[int, str]]) -> bool:
    # True if expression itself is a call to a source (input() etc) or subscript
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id == "input":
        return True
    if isinstance(expr, ast.Subscript) and (_is_sys_argv(expr) or _is_os_environ(expr)):
        return True
    return False


def _is_sys_argv(node: ast.Subscript) -> bool:
    # match sys.argv[...] or sys.argv
    if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
        return node.value.value.id == "sys" and node.value.attr == "argv"
    return False


def _is_os_environ(node: ast.Subscript) -> bool:
    # match os.environ[...] or os.environ
    if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
        return node.value.value.id == "os" and node.value.attr == "environ"
    return False


def _make_finding(node: ast.AST, kind: str, detail: Any) -> Finding:
    return {
        "kind": kind,
        "lineno": getattr(node, "lineno", None),
        "col_offset": getattr(node, "col_offset", None),
        "detail": detail,
    }


def _make_flow(code: str, call_node: ast.Call, arg_node: ast.AST, sink_name: str) -> Finding:
    return {
        "sink": sink_name,
        "lineno": getattr(call_node, "lineno", None),
        "argument": _get_source_segment(code, arg_node),
    }
