from backend.analysis.pycfg_analysis import _CodeAnalyzer, _CFGBuilder
import ast

with open('test_vuln_file.py', 'r') as f:
    code = f.read()

tree = ast.parse(code)

# Find loop_taint function
loop_taint_node = None
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name == "loop_taint":
        loop_taint_node = node
        break

if loop_taint_node:
    print(f"loop_taint body has {len(loop_taint_node.body)} statements:")
    for i, stmt in enumerate(loop_taint_node.body):
        print(f"  {i}: {type(stmt).__name__} - {ast.unparse(stmt)[:60]}")
    
    # Build CFG for this function
    builder = _CFGBuilder(code)
    entry_id, _ = builder._build_block(loop_taint_node.body, next_id=None)
    print(f"\nCFG nodes for loop_taint (entry={entry_id}):")
    for node in builder.nodes:
        print(f"  Node {node.id}: {type(node.ast_node).__name__:15} | {node.code.split(chr(10))[0][:50]:50} | Succ: {node.successors}")
