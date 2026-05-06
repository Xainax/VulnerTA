from backend.analysis.pycfg_analysis import _CFGBuilder, _PyCFGAnalyzer
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
    builder = _CFGBuilder(code)
    entry_id, _ = builder._build_block(loop_taint_node.body, next_id=None)
    
    # Manually analyze with debugging
    analyzer = _PyCFGAnalyzer(code, builder.nodes, builder.edges, entry_id)
    
    state_origins = [dict() for _ in analyzer.nodes]
    worklist = [entry_id] if entry_id is not None else []
    visited = set()
    flows = []
    eval_calls = []
    unsafe_writes = []
    
    iteration = 0
    while worklist and iteration < 20:  # Limit iterations for safety
        iteration += 1
        node_id = worklist.pop(0)
        if node_id is None or node_id in visited:
            continue
        visited.add(node_id)
        node = analyzer.nodes[node_id]
        
        print(f"Iteration {iteration}: Processing node {node_id} ({type(node.ast_node).__name__})")
        print(f"  Code: {node.code[:50]}")
        
        incoming = analyzer._merge_predecessor_states(node_id, state_origins)
        print(f"  Incoming state: {incoming}")
        
        updated = analyzer._process_node(node, incoming, flows, eval_calls, unsafe_writes)
        print(f"  Updated: {updated}, New state: {incoming}")
        
        if updated:
            state_origins[node_id] = incoming
        
        for succ in analyzer.successors.get(node_id, []):
            if succ not in visited and succ not in worklist:
                print(f"  Adding successor {succ} to worklist")
                worklist.append(succ)
        
        print(f"  Worklist: {worklist}, Visited: {visited}")
        print()
