from backend.analysis.pycfg_analysis import _CFGBuilder
import ast

with open('test_vuln_file.py', 'r') as f:
    code = f.read()

tree = ast.parse(code)
builder = _CFGBuilder(code)
entry_id = builder.build(tree)

print(f"Entry ID: {entry_id}")
print(f"Total nodes: {len(builder.nodes)}")

# Map out the CFG structure
print("\nCFG Nodes:")
for node in builder.nodes:
    node_type = type(node.ast_node).__name__
    code_preview = node.code.split('\n')[0][:50] if node.code else "unknown"
    print(f"  Node {node.id}: {node_type:15} | {code_preview:50} | Successors: {node.successors}")
