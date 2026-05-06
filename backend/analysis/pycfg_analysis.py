from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


Finding = Dict[str, Any]


@dataclass
class CFGNode:
    id: int
    ast_node: ast.AST
    code: str
    lineno: Optional[int]
    successors: List[int] = field(default_factory=list)


@dataclass
class CFGEdge:
    source: int
    target: int
    label: str


def analyze_code(code: str, filename: str = "<string>") -> Dict[str, Any]:
    """Analyze Python code with a lightweight CFG-based flow analyzer."""
    try:
        tree = ast.parse(code, filename=filename)
    except SyntaxError:
        return {}

    # Find all function definitions in the code
    analyzer = _CodeAnalyzer(code, filename)
    return analyzer.analyze(tree)


def analyze_files(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = {"tainted_flows": 0, "eval_exec": 0, "unsafe_writes": 0}
    findings = {"tainted_flows": [], "eval_exec": [], "unsafe_writes": []}
    risk_score = 0
    file_results = []

    for f in files:
        code = f.get("content")
        if not code:
            continue
        result = analyze_code(code, filename=f.get("path", "<string>"))
        if not result:
            continue
        file_results.append(result)
        total["tainted_flows"] += result["counts"].get("tainted_flows", 0)
        total["eval_exec"] += result["counts"].get("eval_exec", 0)
        total["unsafe_writes"] += result["counts"].get("unsafe_writes", 0)
        findings["tainted_flows"].extend(result.get("flows", []))
        findings["eval_exec"].extend(result.get("eval_exec_calls", []))
        findings["unsafe_writes"].extend(result.get("unsafe_writes", []))
        risk_score += result["risk"]

    return {
        "files_analyzed": len(file_results),
        "counts": total,
        "risk_score": risk_score,
        "files": file_results,
        "findings": findings,
    }


class _CodeAnalyzer:
    """Analyze Python code by examining each function's CFG."""
    
    def __init__(self, code: str, filename: str = "<string>"):
        self.code = code
        self.filename = filename
    
    def analyze(self, tree: ast.Module) -> Dict[str, Any]:
        """Analyze all functions in the module."""
        total = {"tainted_flows": 0, "eval_exec": 0, "unsafe_writes": 0}
        flows: List[Finding] = []
        eval_calls: List[Finding] = []
        unsafe_writes: List[Finding] = []
        risk_score = 0
        
        # Analyze each function definition
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                result = self._analyze_function(node)
                total["tainted_flows"] += result["counts"]["tainted_flows"]
                total["eval_exec"] += result["counts"]["eval_exec"]
                total["unsafe_writes"] += result["counts"]["unsafe_writes"]
                flows.extend(result.get("flows", []))
                eval_calls.extend(result.get("eval_exec_calls", []))
                unsafe_writes.extend(result.get("unsafe_writes", []))
                risk_score += result["risk"]
        
        return {
            "file": self.filename,
            "counts": total,
            "risk": risk_score,
            "flows": flows,
            "eval_exec_calls": eval_calls,
            "unsafe_writes": unsafe_writes,
            "cfg": {"nodes": [], "edges": []},  # Simplified for now
        }
    
    def _analyze_function(self, func_node: ast.FunctionDef) -> Dict[str, Any]:
        """Analyze a single function's body."""
        if not func_node.body:
            return {
                "counts": {"tainted_flows": 0, "eval_exec": 0, "unsafe_writes": 0},
                "risk": 0,
                "flows": [],
                "eval_exec_calls": [],
                "unsafe_writes": [],
            }
        
        builder = _CFGBuilder(self.code)
        entry_id, _ = builder._build_block(func_node.body, next_id=None)
        
        if entry_id is None:
            return {
                "counts": {"tainted_flows": 0, "eval_exec": 0, "unsafe_writes": 0},
                "risk": 0,
                "flows": [],
                "eval_exec_calls": [],
                "unsafe_writes": [],
            }
        
        analyzer = _PyCFGAnalyzer(self.code, builder.nodes, builder.edges, entry_id)
        return analyzer.analyze(filename=f"{self.filename}::{func_node.name}")


class _CFGBuilder:
    def __init__(self, code: str):
        self.code = code
        self.nodes: List[CFGNode] = []
        self.edges: List[CFGEdge] = []

    def build(self, tree: ast.Module) -> Optional[int]:
        entry_id, _ = self._build_block(tree.body, next_id=None)
        return entry_id

    def _add_node(self, node: ast.AST) -> int:
        node_id = len(self.nodes)
        self.nodes.append(
            CFGNode(
                id=node_id,
                ast_node=node,
                code=_get_source_segment(self.code, node),
                lineno=getattr(node, "lineno", None),
            )
        )
        return node_id

    def _add_edge(self, src: int, dst: int, label: str) -> None:
        if src is None or dst is None:
            return
        self.nodes[src].successors.append(dst)
        self.edges.append(CFGEdge(source=src, target=dst, label=label))

    def _build_block(self, stmts: List[ast.stmt], next_id: Optional[int]) -> Tuple[Optional[int], List[int]]:
        entry_id: Optional[int] = None
        exit_ids: List[int] = []
        current_next = next_id

        for stmt in reversed(stmts):
            if isinstance(stmt, ast.FunctionDef):
                # Create a node for the function definition and analyze its body
                func_id = self._add_node(stmt)
                if stmt.body:
                    body_entry, body_exits = self._build_block(stmt.body, None)  # Functions don't have a next statement
                    if body_entry is not None:
                        self._add_edge(func_id, body_entry, "body")
                entry_id = func_id
                exit_ids = [func_id]
                current_next = func_id
            elif isinstance(stmt, ast.If):
                cond_id = self._add_node(stmt)
                then_entry, then_exits = self._build_block(stmt.body, current_next)
                else_entry, else_exits = self._build_block(stmt.orelse, current_next) if stmt.orelse else (current_next, [current_next] if current_next is not None else [])

                if then_entry is not None:
                    self._add_edge(cond_id, then_entry, "true")
                elif current_next is not None:
                    self._add_edge(cond_id, current_next, "true")

                if else_entry is not None:
                    self._add_edge(cond_id, else_entry, "false")
                elif current_next is not None:
                    self._add_edge(cond_id, current_next, "false")

                entry_id = cond_id
                exit_ids = then_exits + else_exits
                current_next = cond_id
            elif isinstance(stmt, (ast.For, ast.While)):
                loop_id = self._add_node(stmt)
                body_entry, body_exits = self._build_block(stmt.body, loop_id)
                if body_entry is not None:
                    self._add_edge(loop_id, body_entry, "loop")
                if current_next is not None:
                    self._add_edge(loop_id, current_next, "exit")
                for exit_id in body_exits:
                    if exit_id is not None:
                        self._add_edge(exit_id, loop_id, "back")
                entry_id = loop_id
                exit_ids = [loop_id]
                current_next = loop_id
            else:
                stmt_id = self._add_node(stmt)
                if current_next is not None:
                    self._add_edge(stmt_id, current_next, "next")
                entry_id = stmt_id
                exit_ids = [stmt_id]
                current_next = stmt_id

        return entry_id, exit_ids


class _PyCFGAnalyzer:
    def __init__(self, code: str, nodes: List[CFGNode], edges: List[CFGEdge], entry_id: Optional[int]):
        self.code = code
        self.nodes = nodes
        self.edges = edges
        self.entry_id = entry_id
        self.successors = {node.id: list(node.successors) for node in nodes}
        self.predecessors: Dict[int, List[int]] = {node.id: [] for node in nodes}
        for edge in edges:
            self.predecessors[edge.target].append(edge.source)

    def analyze(self, filename: str = "<string>") -> Dict[str, Any]:
        state_origins: List[Dict[str, Set[int]]] = [dict() for _ in self.nodes]
        worklist = [self.entry_id] if self.entry_id is not None else []
        visited: Set[int] = set()

        flows: List[Finding] = []
        eval_calls: List[Finding] = []
        unsafe_writes: List[Finding] = []

        while worklist:
            node_id = worklist.pop(0)
            if node_id is None or node_id in visited:
                continue
            visited.add(node_id)
            node = self.nodes[node_id]
            incoming = self._merge_predecessor_states(node_id, state_origins)
            updated = self._process_node(node, incoming, flows, eval_calls, unsafe_writes)
            if updated:
                state_origins[node_id] = incoming
            for succ in self.successors.get(node_id, []):
                if succ not in visited:
                    worklist.append(succ)

        counts = {
            "tainted_flows": len(flows),
            "eval_exec": len(eval_calls),
            "unsafe_writes": len(unsafe_writes),
        }
        risk = counts["tainted_flows"] * 5 + counts["eval_exec"] * 3 + counts["unsafe_writes"] * 2

        return {
            "file": filename,
            "counts": counts,
            "risk": risk,
            "flows": flows,
            "eval_exec_calls": eval_calls,
            "unsafe_writes": unsafe_writes,
            "cfg": {
                "nodes": [
                    {
                        "id": node.id,
                        "lineno": node.lineno,
                        "code": node.code,
                        "successors": node.successors,
                    }
                    for node in self.nodes
                ],
                "edges": [edge.__dict__ for edge in self.edges],
            },
        }

    def _merge_predecessor_states(self, node_id: int, state_origins: List[Dict[str, Set[int]]]) -> Dict[str, Set[int]]:
        merged: Dict[str, Set[int]] = {}
        predecessors = self.predecessors.get(node_id, [])
        if not predecessors:
            return merged
        for pred in predecessors:
            for var, origins in state_origins[pred].items():
                merged.setdefault(var, set()).update(origins)
        return merged

    def _process_node(
        self,
        node: CFGNode,
        state: Dict[str, Set[int]],
        flows: List[Finding],
        eval_calls: List[Finding],
        unsafe_writes: List[Finding],
    ) -> bool:
        original_state = {k: set(v) for k, v in state.items()}
        stmt = node.ast_node

        # Handle assignment statements - mark variables as tainted if RHS has tainted sources
        if isinstance(stmt, ast.Assign):
            origins = self._expr_origins(stmt.value, state, node.id)
            for target in stmt.targets:
                for name in _extract_target_names(target):
                    if origins:
                        state[name] = origins
        
        # Handle augmented assignment (+=, etc)
        elif isinstance(stmt, ast.AugAssign):
            origins = self._expr_origins(stmt.value, state, node.id)
            target_names = _extract_target_names(stmt.target)
            current_origins = set()
            for name in target_names:
                current_origins.update(state.get(name, set()))
            current_origins.update(origins)
            for name in target_names:
                if current_origins:
                    state[name] = current_origins
        
        # Handle with statements (context managers like open())
        elif isinstance(stmt, ast.With):
            for item in stmt.items:
                if item.optional_vars is not None:
                    origins = self._expr_origins(item.context_expr, state, node.id)
                    for name in _extract_target_names(item.optional_vars):
                        if origins:
                            state[name] = origins

        # Check for calls in different contexts
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            self._check_call(stmt.value, node, state, flows, eval_calls)
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            self._check_call(stmt.value, node, state, flows, eval_calls)
        elif isinstance(stmt, ast.Call):
            self._check_call(stmt, node, state, flows, eval_calls)
        elif isinstance(stmt, ast.With):
            # Check calls in with statement context expressions
            for item in stmt.items:
                if isinstance(item.context_expr, ast.Call):
                    self._check_call(item.context_expr, node, state, flows, eval_calls)

        # Check for unsafe file writes
        if self._is_unsafe_write(stmt, state, node.id):
            unsafe_writes.append(_make_finding(stmt, "unsafe_write", _get_source_segment(self.code, stmt)))

        # Return True if state changed
        return state != original_state

    def _expr_origins(self, expr: ast.AST, state: Dict[str, Set[int]], current_node_id: int) -> Set[int]:
        origins: Set[int] = set()
        if isinstance(expr, ast.Name):
            origins.update(state.get(expr.id, set()))
        elif isinstance(expr, ast.Call):
            if _is_source_call(expr):
                origins.add(current_node_id)
            # Check if this is a method call on a tainted object
            if isinstance(expr.func, ast.Attribute):
                # E.g., user_input.replace(...) - the .replace() call preserves taint
                origins.update(self._expr_origins(expr.func.value, state, current_node_id))
            # Check arguments
            for arg in expr.args:
                origins.update(self._expr_origins(arg, state, current_node_id))
            for kw in expr.keywords:
                origins.update(self._expr_origins(kw.value, state, current_node_id))
        elif isinstance(expr, ast.Attribute):
            origins.update(self._expr_origins(expr.value, state, current_node_id))
        elif isinstance(expr, ast.Subscript):
            if _is_source_subscript(expr):
                origins.add(current_node_id)
            else:
                origins.update(self._expr_origins(expr.value, state, current_node_id))
                origins.update(self._expr_origins(expr.slice, state, current_node_id))
        elif isinstance(expr, ast.BinOp):
            origins.update(self._expr_origins(expr.left, state, current_node_id))
            origins.update(self._expr_origins(expr.right, state, current_node_id))
        elif isinstance(expr, ast.UnaryOp):
            origins.update(self._expr_origins(expr.operand, state, current_node_id))
        elif isinstance(expr, ast.Compare):
            origins.update(self._expr_origins(expr.left, state, current_node_id))
            for comparator in expr.comparators:
                origins.update(self._expr_origins(comparator, state, current_node_id))
        elif isinstance(expr, ast.Tuple) or isinstance(expr, ast.List) or isinstance(expr, ast.Set):
            for elt in expr.elts:
                origins.update(self._expr_origins(elt, state, current_node_id))
        elif isinstance(expr, ast.Dict):
            for key in expr.keys:
                if key is not None:
                    origins.update(self._expr_origins(key, state, current_node_id))
            for value in expr.values:
                origins.update(self._expr_origins(value, state, current_node_id))
        return origins

    def _check_call(
        self,
        call_node: ast.Call,
        node: CFGNode,
        state: Dict[str, Set[int]],
        flows: List[Finding],
        eval_calls: List[Finding],
    ) -> None:
        name = _get_full_call_name(call_node)
        if name in ("eval", "exec"):
            eval_calls.append(_make_finding(call_node, "eval_exec", name))
            if self._call_has_tainted_arg(call_node, state, node.id):
                flows.append(self._make_flow(call_node, node, name, state))
        elif name in ("os.system", "subprocess.call", "subprocess.Popen", "subprocess.run"):
            if self._call_has_tainted_arg(call_node, state, node.id):
                flows.append(self._make_flow(call_node, node, name, state))

    def _call_has_tainted_arg(self, call_node: ast.Call, state: Dict[str, Set[int]], current_node_id: int) -> bool:
        for arg in call_node.args:
            if self._expr_origins(arg, state, current_node_id):
                return True
        for kw in call_node.keywords:
            if self._expr_origins(kw.value, state, current_node_id):
                return True
        return False

    def _make_flow(self, call_node: ast.Call, node: CFGNode, sink_name: str, state: Dict[str, Set[int]]) -> Finding:
        arg_source_text = _get_source_segment(self.code, call_node)
        origin_ids = set()
        for arg in call_node.args:
            origin_ids.update(self._expr_origins(arg, state, node.id))
        for kw in call_node.keywords:
            origin_ids.update(self._expr_origins(kw.value, state, node.id))
        path = self._find_path(origin_ids, node.id)
        return {
            "sink": sink_name,
            "lineno": node.lineno,
            "argument": arg_source_text,
            "source_nodes": sorted(origin_ids),
            "path": path,
        }

    def _find_path(self, origin_ids: Set[int], sink_id: int) -> List[str]:
        if not origin_ids:
            return []
        queue = []
        visited = set()
        for origin in origin_ids:
            queue.append((origin, [origin]))
            visited.add(origin)
        while queue:
            current, path = queue.pop(0)
            if current == sink_id:
                return [self.nodes[node_id].code for node_id in path if self.nodes[node_id].code]
            for succ in self.successors.get(current, []):
                if succ in visited:
                    continue
                visited.add(succ)
                queue.append((succ, path + [succ]))
        return [self.nodes[sink_id].code] if self.nodes[sink_id].code else []

    def _is_unsafe_write(self, stmt: ast.AST, state: Dict[str, Set[int]], current_node_id: int) -> bool:
        """Check if this statement performs an unsafe file write with tainted filename."""
        call_node = None
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call_node = stmt.value
        elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            call_node = stmt.value
        elif isinstance(stmt, ast.With):
            # Check with statement context managers
            for item in stmt.items:
                if isinstance(item.context_expr, ast.Call) and _get_full_call_name(item.context_expr) == "open":
                    call_node = item.context_expr
                    break
        else:
            return False

        if call_node is None or _get_full_call_name(call_node) != "open":
            return False

        # Check if filename argument is tainted
        if call_node.args and self._expr_origins(call_node.args[0], state, current_node_id):
            return True

        # Check mode
        mode = None
        if len(call_node.args) >= 2:
            arg = call_node.args[1]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                mode = arg.value
        for kw in call_node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                mode = kw.value.value
        return mode is not None and any(c in mode for c in ("w", "a"))


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
        parts = []
        curr = node.func
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return ".".join(reversed(parts))
    return ""


def _extract_target_names(target: ast.AST) -> List[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    elif isinstance(target, (ast.Tuple, ast.List)):
        names: List[str] = []
        for elt in target.elts:
            names.extend(_extract_target_names(elt))
        return names
    return []


def _is_source_call(node: ast.Call) -> bool:
    """Check if this call is a source of tainted data."""
    name = _get_full_call_name(node)
    return name == "input"


def _is_source_subscript(node: ast.Subscript) -> bool:
    """Check if this subscript access is a source of tainted data."""
    return _is_sys_argv(node) or _is_os_environ(node)


def _is_sys_argv(node: ast.Subscript) -> bool:
    if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
        return node.value.value.id == "sys" and node.value.attr == "argv"
    return False


def _is_os_environ(node: ast.Subscript) -> bool:
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
