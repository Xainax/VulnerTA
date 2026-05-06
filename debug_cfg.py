from backend.analysis.pycfg_analysis import _CFGBuilder, _PyCFGAnalyzer
import ast

# Read the test file
with open('test_vuln_file.py', 'r') as f:
    code = f.read()

print("Testing CFG building...")

# Parse and build CFG
tree = ast.parse(code)
builder = _CFGBuilder(code)
entry_id = builder.build(tree)

print(f"Built CFG with {len(builder.nodes)} nodes and {len(builder.edges)} edges")
print(f"Entry ID: {entry_id}")

# Print some nodes to see what was built
for i, node in enumerate(builder.nodes[:10]):
    print(f"Node {node.id}: {node.code[:60]}...")
    print(f"  Successors: {node.successors}")

# Test a simple function analysis
analyzer = _PyCFGAnalyzer(code, builder.nodes, builder.edges, entry_id)

# Find a function node
func_node = None
for node in builder.nodes:
    if isinstance(node.ast_node, ast.FunctionDef) and node.ast_node.name == "tainted_exec":
        func_node = node
        break

if func_node:
    print(f"\nAnalyzing function: {func_node.ast_node.name}")
    print(f"Function body has {len(func_node.ast_node.body)} statements")

    # Check if we can find input() and eval() calls
    for stmt in func_node.ast_node.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            call_name = _get_full_call_name(stmt.value)
            print(f"Found assignment with call: {call_name}")
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call_name = _get_full_call_name(stmt.value)
            print(f"Found expression call: {call_name}")
else:
    print("Could not find tainted_exec function")

def _get_full_call_name(node):
    if isinstance(node, ast.Call):
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