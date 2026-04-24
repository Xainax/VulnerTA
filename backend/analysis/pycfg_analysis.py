import ast
from typing import Any, Dict, List, Tuple

try:
    from ast import unparse as ast_unparse
except ImportError:
    import astunparse
    ast_unparse = astunparse.unparse


class CFGNode(dict):
    registry = 0
    cache: Dict[int, "CFGNode"] = {}
    stack: List["CFGNode"] = []

    @classmethod
    def reset_cache(cls) -> None:
        cls.registry = 0
        cls.cache = {}
        cls.stack = []

    def __init__(self, parents: List["CFGNode"] = [], ast: ast.AST = None):
        assert type(parents) is list
        self.parents = parents
        self.calls: List[str] = []
        self.children: List["CFGNode"] = []
        self.ast_node = ast
        self.rid = CFGNode.registry
        CFGNode.cache[self.rid] = self
        CFGNode.registry += 1

    def lineno(self) -> int:
        return self.ast_node.lineno if hasattr(self.ast_node, "lineno") else 0

    def __str__(self) -> str:
        return "id:%d line[%d] parents: %s : %s" % (
            self.rid,
            self.lineno(),
            str([p.rid for p in self.parents]),
            self.source(),
        )

    def __repr__(self) -> str:
        return str(self)

    def add_child(self, c: "CFGNode") -> None:
        if c not in self.children:
            self.children.append(c)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CFGNode) and self.rid == other.rid

    def add_parent(self, p: "CFGNode") -> None:
        if p not in self.parents:
            self.parents.append(p)

    def add_parents(self, ps: List["CFGNode"]) -> None:
        for p in ps:
            self.add_parent(p)

    def add_calls(self, func: str) -> None:
        self.calls.append(func)

    def source(self) -> str:
        try:
            return ast_unparse(self.ast_node).strip()
        except Exception:
            return ""

    def to_json(self) -> Dict[str, Any]:
        return {
            "id": self.rid,
            "parents": [p.rid for p in self.parents],
            "children": [c.rid for c in self.children],
            "calls": self.calls,
            "at": self.lineno(),
            "ast": self.source(),
        }


def compute_dominator(cfg: Dict[int, Dict[str, Any]], start: int = 0, key: str = "parents") -> Dict[int, Any]:
    dominator: Dict[int, Any] = {}
    dominator[start] = {start}
    all_nodes = set(cfg.keys())
    rem_nodes = all_nodes - {start}

    for n in rem_nodes:
        dominator[n] = set(all_nodes)

    changed = True
    while changed:
        changed = False
        for n in rem_nodes:
            predecessors = cfg[n][key]
            doms = [dominator[p] for p in predecessors] if predecessors else []
            intersection = set.intersection(*doms) if doms else set()
            new_dom = {n} | intersection
            if dominator[n] != new_dom:
                dominator[n] = new_dom
                changed = True
    return dominator


class PyCFG:
    def __init__(self):
        self.founder = CFGNode(parents=[], ast=ast.parse("start").body[0])
        self.founder.ast_node.lineno = 0
        self.functions: Dict[str, List[CFGNode]] = {}
        self.functions_node: Dict[int, str] = {}

    def parse(self, src: str) -> ast.AST:
        return ast.parse(src)

    def walk(self, node: ast.AST, myparents: List[CFGNode]) -> List[CFGNode]:
        if node is None:
            return []
        fname = f"on_{node.__class__.__name__.lower()}"
        if hasattr(self, fname):
            return getattr(self, fname)(node, myparents)
        return myparents

    def on_module(self, node: ast.Module, myparents: List[CFGNode]) -> List[CFGNode]:
        p = myparents
        for n in node.body:
            p = self.walk(n, p)
        return p

    def on_assign(self, node: ast.Assign, myparents: List[CFGNode]) -> List[CFGNode]:
        if len(node.targets) > 1:
            raise NotImplementedError("Parallel assignments are not supported")
        p = [CFGNode(parents=myparents, ast=node)]
        return self.walk(node.value, p)

    def on_pass(self, node: ast.Pass, myparents: List[CFGNode]) -> List[CFGNode]:
        return [CFGNode(parents=myparents, ast=node)]

    def on_break(self, node: ast.Break, myparents: List[CFGNode]) -> List[CFGNode]:
        parent = myparents[0]
        while not hasattr(parent, "exit_nodes"):
            parent = parent.parents[0]
        p = CFGNode(parents=myparents, ast=node)
        parent.exit_nodes.append(p)
        return []

    def on_continue(self, node: ast.Continue, myparents: List[CFGNode]) -> List[CFGNode]:
        parent = myparents[0]
        while not hasattr(parent, "exit_nodes"):
            parent = parent.parents[0]
        p = CFGNode(parents=myparents, ast=node)
        parent.add_parent(p)
        return []

    def on_for(self, node: ast.For, myparents: List[CFGNode]) -> List[CFGNode]:
        _test_node = CFGNode(
            parents=myparents,
            ast=ast.parse(f"_for: True if {ast_unparse(node.iter).strip()} else False").body[0],
        )
        ast.copy_location(_test_node.ast_node, node)
        _test_node.exit_nodes = []
        test_node = self.walk(node.iter, [_test_node])

        extract_node = CFGNode(
            parents=[_test_node],
            ast=ast.parse(
                f"{ast_unparse(node.target).strip()} = {ast_unparse(node.iter).strip()}.shift()"
            ).body[0],
        )
        ast.copy_location(extract_node.ast_node, _test_node.ast_node)

        p1 = [extract_node]
        for n in node.body:
            p1 = self.walk(n, p1)
        _test_node.add_parents(p1)
        return _test_node.exit_nodes + test_node

    def on_while(self, node: ast.While, myparents: List[CFGNode]) -> List[CFGNode]:
        _test_node = CFGNode(
            parents=myparents,
            ast=ast.parse(f"_while: {ast_unparse(node.test).strip()}").body[0],
        )
        ast.copy_location(_test_node.ast_node, node.test)
        _test_node.exit_nodes = []
        test_node = self.walk(node.test, [_test_node])
        p1 = test_node
        for n in node.body:
            p1 = self.walk(n, p1)
        _test_node.add_parents(p1)
        return _test_node.exit_nodes + test_node

    def on_if(self, node: ast.If, myparents: List[CFGNode]) -> List[CFGNode]:
        _test_node = CFGNode(
            parents=myparents,
            ast=ast.parse(f"_if: {ast_unparse(node.test).strip()}").body[0],
        )
        ast.copy_location(_test_node.ast_node, node.test)
        test_node = self.walk(node.test, [_test_node])
        g1 = test_node
        for n in node.body:
            g1 = self.walk(n, g1)
        g2 = test_node
        for n in node.orelse:
            g2 = self.walk(n, g2)
        return g1 + g2

    def on_binop(self, node: ast.BinOp, myparents: List[CFGNode]) -> List[CFGNode]:
        left = self.walk(node.left, myparents)
        return self.walk(node.right, left)

    def on_compare(self, node: ast.Compare, myparents: List[CFGNode]) -> List[CFGNode]:
        left = self.walk(node.left, myparents)
        return self.walk(node.comparators[0], left)

    def on_unaryop(self, node: ast.UnaryOp, myparents: List[CFGNode]) -> List[CFGNode]:
        return self.walk(node.operand, myparents)

    def on_call(self, node: ast.Call, myparents: List[CFGNode]) -> List[CFGNode]:
        def get_func_name(inner: ast.Call | ast.Attribute | ast.Name) -> str:
            if isinstance(inner, ast.Name):
                return inner.id
            if isinstance(inner, ast.Attribute):
                return inner.attr
            if isinstance(inner, ast.Call):
                return get_func_name(inner.func)
            raise Exception(str(type(inner)))

        p = myparents
        for a in node.args:
            p = self.walk(a, p)
        mid = get_func_name(node)
        myparents[0].add_calls(mid)
        for c in p:
            c.calllink = 0
        return p

    def on_expr(self, node: ast.Expr, myparents: List[CFGNode]) -> List[CFGNode]:
        p = [CFGNode(parents=myparents, ast=node)]
        return self.walk(node.value, p)

    def on_return(self, node: ast.Return, myparents: List[CFGNode]) -> List[CFGNode]:
        parent = myparents[0]
        val_node = self.walk(node.value, myparents)
        while not hasattr(parent, "return_nodes"):
            parent = parent.parents[0]
        p = CFGNode(parents=val_node, ast=node)
        parent.return_nodes.append(p)
        return []

    def on_functiondef(self, node: ast.FunctionDef, myparents: List[CFGNode]) -> List[CFGNode]:
        enter_node = CFGNode(
            parents=[],
            ast=ast.parse(
                f"enter: {node.name}({', '.join([a.arg for a in node.args.args])})"
            ).body[0],
        )
        enter_node.calleelink = True
        ast.copy_location(enter_node.ast_node, node)
        exit_node = CFGNode(
            parents=[],
            ast=ast.parse(
                f"exit: {node.name}({', '.join([a.arg for a in node.args.args])})"
            ).body[0],
        )
        exit_node.fn_exit_node = True
        ast.copy_location(exit_node.ast_node, node)
        enter_node.return_nodes = []

        p = [enter_node]
        for n in node.body:
            p = self.walk(n, p)

        for n in p:
            if n not in enter_node.return_nodes:
                enter_node.return_nodes.append(n)

        for n in enter_node.return_nodes:
            exit_node.add_parent(n)

        self.functions[node.name] = [enter_node, exit_node]
        self.functions_node[enter_node.lineno()] = node.name
        return myparents

    def get_defining_function(self, node: CFGNode) -> str:
        if node.lineno() in self.functions_node:
            return self.functions_node[node.lineno()]
        if not node.parents:
            self.functions_node[node.lineno()] = ""
            return ""
        val = self.get_defining_function(node.parents[0])
        self.functions_node[node.lineno()] = val
        return val

    def link_functions(self) -> None:
        for node in CFGNode.cache.values():
            if node.calls:
                for call in node.calls:
                    if call in self.functions:
                        enter, exit_node = self.functions[call]
                        enter.add_parent(node)
                        if node.children:
                            assert node.calllink > -1
                            node.calllink += 1
                            for child in node.children:
                                child.add_parent(exit_node)

    def update_functions(self) -> None:
        for node in CFGNode.cache.values():
            self.get_defining_function(node)

    def update_children(self) -> None:
        for node in CFGNode.cache.values():
            for parent in node.parents:
                parent.add_child(node)

    def gen_cfg(self, src: str) -> None:
        CFGNode.reset_cache()
        self.founder = CFGNode(parents=[], ast=ast.parse("start").body[0])
        self.founder.ast_node.lineno = 0
        node = self.parse(src)
        nodes = self.walk(node, [self.founder])
        self.last_node = CFGNode(parents=nodes, ast=ast.parse("stop").body[0])
        ast.copy_location(self.last_node.ast_node, self.founder.ast_node)
        self.update_children()
        self.update_functions()
        self.link_functions()


def get_cfg_from_code(code: str) -> Dict[str, Any]:
    cfg = PyCFG()
    cfg.gen_cfg(code)

    nodes: List[Dict[str, Any]] = []
    for node in CFGNode.cache.values():
        nodes.append(
            {
                "id": node.rid,
                "ast": node.source(),
                "lineno": node.lineno(),
                "parents": [p.rid for p in node.parents],
                "children": [c.rid for c in node.children],
                "calls": list(node.calls),
                "function": cfg.functions_node.get(node.lineno(), ""),
            }
        )

    graph: Dict[int, Dict[str, List[int]]] = {
        node.rid: {"parents": [p.rid for p in node.parents], "children": [c.rid for c in node.children]}
        for node in CFGNode.cache.values()
    }
    dominators = compute_dominator(graph, start=cfg.founder.rid)
    postdominators = compute_dominator(graph, start=cfg.last_node.rid, key="children")

    edges: List[Dict[str, int]] = []
    for node in CFGNode.cache.values():
        for parent in node.parents:
            edges.append({"from": parent.rid, "to": node.rid})

    return {
        "nodes": nodes,
        "edges": edges,
        "start_line": cfg.founder.lineno(),
        "end_line": cfg.last_node.lineno(),
        "dominators": {k: sorted(list(v)) for k, v in dominators.items()},
        "postdominators": {k: sorted(list(v)) for k, v in postdominators.items()},
    }
