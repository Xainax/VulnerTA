import ast
from typing import Any, Dict, List, Tuple

from backend.analysis.pycfg_analysis import get_cfg_from_code

# types for readability
Finding = Dict[str, Any]

# rule catalog definitions

SOURCE_RULES = [
    ("input", lambda node: isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input"),
    ("sys.argv", lambda node: isinstance(node, ast.Subscript) and _is_sys_argv(node)),
    ("os.environ", lambda node: isinstance(node, ast.Subscript) and _is_os_environ(node)),
]


SINK_RULES = [
    {"kind": "eval_exec", "calls": ["eval", "exec"], "check": None, "track_args": True},
    {
        "kind": "os_command",
        "calls": ["os.system", "subprocess.call", "subprocess.Popen", "subprocess.run"],
        "check": None,
        "track_args": True,
    },
    {
        "kind": "unsafe_write",
        "calls": ["open"],
        # only report when mode contains w or a
        "check": lambda node: _open_mode_is_write(node),
        "track_args": False,
    },
]


def _open_mode_is_write(node: ast.Call) -> bool:
    # used by the unsafe_write sink rule
    mode = None
    if len(node.args) >= 2:
        m = node.args[1]
        if isinstance(m, ast.Constant) and isinstance(m.value, str):
            mode = m.value
    elif any(kw.arg == "mode" for kw in node.keywords):
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = kw.value.value
    return bool(mode and any(c in mode for c in ("w", "a")))

# helper used by the source rule lambdas; defined here so the lambdas can
# refer to it below

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

class _SourceVisitor(ast.NodeVisitor):

    def __init__(self, code: str):
        self.code = code
        self.tainted_vars = set()  # variable names that are tainted
        # map var name -> list of (lineno, kind, segment)
        self.origins: Dict[str, List[Tuple[int, str, str]]] = {}
        # record direct source expressions (lineno, kind, source_segment)
        self.sources: List[Tuple[int, str, str]] = []

    def _record_source(self, node: ast.AST):
        """If node matches a source rule return its kind, otherwise None."""
        for kind, matcher in SOURCE_RULES:
            try:
                if matcher(node):
                    return kind
            except Exception:
                # rule matcher may assume certain node attributes; ignore
                pass
        return None

    def visit_Assign(self, node: ast.Assign):
        kind = self._record_source(node.value)
        if kind:
            segment = _get_source_segment(self.code, node.value)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
                    self.origins.setdefault(target.id, []).append(
                        (node.lineno, kind, segment)
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        kind = self._record_source(node)
        if kind:
            self.sources.append((node.lineno, kind, _get_source_segment(self.code, node)))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        kind = self._record_source(node)
        if kind:
            self.sources.append((node.lineno, kind, _get_source_segment(self.code, node)))
        self.generic_visit(node)


class _SinkVisitor(ast.NodeVisitor):

    def __init__(self, code: str, tainted_vars: set, origins: Dict[str, List[Tuple[int, str, str]]], source_exprs: List[Tuple[int, str, str]]):
        self.code = code
        self.tainted_vars = tainted_vars
        self.origins = origins
        self.source_exprs = source_exprs

        # accumulate findings by kind; some rules populate specific lists to
        # maintain backwards compatibility with earlier APIs.
        self.flows: List[Finding] = []
        self.eval_exec_calls: List[Finding] = []
        self.unsafe_writes: List[Finding] = []

    def visit_Call(self, node: ast.Call):
        fname = _get_full_call_name(node)
        for rule in SINK_RULES:
            if fname in rule["calls"]:
                if rule["check"] is None or rule["check"](node):
                    finding = _make_finding(node, rule["kind"], fname)
                    # maintain the old list names for tests
                    if rule["kind"] == "eval_exec":
                        self.eval_exec_calls.append(finding)
                    elif rule["kind"] == "unsafe_write":
                        self.unsafe_writes.append(finding)
                    # track flows if required
                    if rule["track_args"]:
                        for arg in node.args:
                            if _expr_is_tainted(arg, self.tainted_vars) or _expr_is_source(arg, self.source_exprs, self.code):
                                self.flows.append(_make_flow(self.code, node, arg, rule["kind"], self.origins, self.source_exprs))
        self.generic_visit(node)

# analyze Python source code and produce structured findings
def analyze_code(code: str, filename: str = "<string>") -> Dict[str, Any]:
    try:
        tree = ast.parse(code, filename=filename)
    except SyntaxError:
        # skip files with parse errors
        return {}

    source_vis = _SourceVisitor(code)
    source_vis.visit(tree)

    sink_vis = _SinkVisitor(code, source_vis.tainted_vars, source_vis.origins, source_vis.sources)
    sink_vis.visit(tree)

    counts = {
        "tainted_flows": len(sink_vis.flows),
        "eval_exec": len(sink_vis.eval_exec_calls),
        "unsafe_writes": len(sink_vis.unsafe_writes),
    }
    # simple risk formula: weighted sum
    risk = counts["tainted_flows"] * 5 + counts["eval_exec"] * 3 + counts["unsafe_writes"] * 2
    cfg = get_cfg_from_code(code)

    return {
        "file": filename,
        "counts": counts,
        "risk": risk,
        "flows": sink_vis.flows,
        "eval_exec_calls": sink_vis.eval_exec_calls,
        "unsafe_writes": sink_vis.unsafe_writes,
        "cfg": cfg,
    }


def analyze_files(files: List[Dict[str, Any]]) -> Dict[str, Any]:
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


# ---------------------------------------------------------------------------
# helpers for pretty printing
# ---------------------------------------------------------------------------

# format flow to be easier to understand for users;
def format_flow(flow: Finding, risk_label: str = None) -> str:
    parts = []
    trace = flow.get("trace", "")
    # parse trace like "input(input())@2" or potentially chained strings
    source_part = ""
    source_line = None
    if "@" in trace:
        src, ln = trace.rsplit("@", 1)
        source_part = src
        try:
            source_line = int(ln)
        except ValueError:
            source_line = None
    else:
        source_part = trace
    if source_part:
        parts.append(f"Source: {source_part}" + (f" at line {source_line}" if source_line else ""))
    arg = flow.get("argument")
    if arg and arg.isidentifier():
        parts.append(f"→ Assigned to: {arg}")
    sink = flow.get("sink")
    line = flow.get("lineno")
    if sink:
        parts.append(f"→ Passed to: {sink}()" + (f" at line {line}" if line else ""))
    if risk_label:
        parts.append(f"Risk: {risk_label}")
    vulnerabilities = flow.get("vulnerabilities")
    if vulnerabilities:
        parts.append(f"Vulnerabilities: {', '.join(vulnerabilities)}")
    # join with newlines and an initial heading
    report = "[TAINT FLOW]\n\n" + "\n".join(parts)
    return report


def _risk_label_for_sink(kind: str) -> str:
    mapping = {
        "eval_exec": "Remote Code Execution",
        "os_command": "OS Command Injection",
        "unsafe_write": "Unsafe File Write",
    }
    return mapping.get(kind, "")


def _source_vulnerability_label(trace: str) -> str:
    if not trace:
        return ""
    if any(token in trace for token in ("input(", "sys.argv", "os.environ")):
        return "Input Handling"
    return ""


def _make_vulnerability_labels(sink_name: str, trace: str) -> List[str]:
    labels: List[str] = []
    source_label = _source_vulnerability_label(trace)
    if source_label:
        labels.append(source_label)
    risk_label = _risk_label_for_sink(sink_name)
    if risk_label:
        labels.append(risk_label)
    return labels


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


def _expr_is_source(expr: ast.AST, source_records: List[Tuple[int, str, str]], code: str) -> bool:
    """Return True if the expression itself matches one of the recorded source
    expressions.  ``source_records`` is the list produced by ``_SourceVisitor``
    storing (lineno, kind, segment).
    """
    if not source_records:
        return False
    seg = _get_source_segment(code, expr) if hasattr(expr, "lineno") else ""
    for _, _, recorded in source_records:
        if recorded and seg and recorded == seg:
            return True
    return False


def _make_finding(node: ast.AST, kind: str, detail: Any) -> Finding:
    return {
        "kind": kind,
        "lineno": getattr(node, "lineno", None),
        "col_offset": getattr(node, "col_offset", None),
        "detail": detail,
    }


def _make_flow(
    code: str,
    call_node: ast.Call,
    arg_node: ast.AST,
    sink_name: str,
    origins: Dict[str, List[Tuple[int, str, str]]],
    source_exprs: List[Tuple[int, str, str]],
) -> Finding:
    flow = {
        "sink": sink_name,
        "lineno": getattr(call_node, "lineno", None),
        "argument": _get_source_segment(code, arg_node),
    }
    trace = _build_flow_trace(arg_node, origins, source_exprs, code)
    if trace:
        flow["trace"] = trace
    flow["vulnerabilities"] = _make_vulnerability_labels(sink_name, trace)
    return flow


def _build_flow_trace(
    expr: ast.AST,
    origins: Dict[str, List[Tuple[int, str, str]]],
    source_exprs: List[Tuple[int, str, str]],
    code: str,
) -> str:
    # variable reference
    if isinstance(expr, ast.Name):
        name = expr.id
        if name in origins:
            parts = []
            for lineno, kind, segment in origins[name]:
                parts.append(f"{kind}({segment})@{lineno}")
            return " -> ".join(parts)
    # direct source call or subscript
    seg = _get_source_segment(code, expr)
    for lineno, kind, segment in source_exprs:
        if segment and seg and segment == seg:
            return f"{kind}({segment})@{lineno}"
    return "tainted"
