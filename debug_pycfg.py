from backend.analysis.pycfg_analysis import analyze_code
import ast

# Read the test file
with open('test_vuln_file.py', 'r') as f:
    code = f.read()

print("Code to analyze:")
print("=" * 50)
print(code)
print("=" * 50)

# Parse the AST to see the structure
tree = ast.parse(code)
print(f"\nAST has {len(tree.body)} top-level statements")

# Analyze with PyCFG
result = analyze_code(code, 'test_vuln_file.py')
print('\nPyCFG Analysis Results:')
print(f"Counts: {result['counts']}")
print(f"Risk: {result['risk']}")
print(f"Flows found: {len(result.get('flows', []))}")
print(f"Eval calls found: {len(result.get('eval_exec_calls', []))}")
print(f"Unsafe writes found: {len(result.get('unsafe_writes', []))}")

# Check CFG
cfg = result.get('cfg', {})
print(f"\nCFG has {len(cfg.get('nodes', []))} nodes and {len(cfg.get('edges', []))} edges")

# Print some nodes
nodes = cfg.get('nodes', [])
for i, node in enumerate(nodes[:5]):  # First 5 nodes
    print(f"Node {i}: {node['code'][:50]}...")