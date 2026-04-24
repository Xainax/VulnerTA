from backend.analysis.pycfg_analysis import analyze_code as pycfg_analyze
from backend.analysis.ast_analysis import analyze_code as ast_analyze

with open('test_vuln_file.py', 'r') as f:
    code = f.read()

pycfg_result = pycfg_analyze(code, 'test_vuln_file.py')
ast_result = ast_analyze(code, 'test_vuln_file.py')

print("=== PYCFG TAINTED FLOWS ===")
for flow in pycfg_result['flows']:
    print(f"  Line {flow.get('lineno')}: {flow.get('sink')} - {flow.get('argument')[:50]}")

print("\n=== AST TAINTED FLOWS ===")
for flow in ast_result['flows']:
    print(f"  Line {flow.get('lineno')}: {flow.get('sink')} - {flow.get('detail', '')[:50]}")

print("\n=== PYCFG EVAL/EXEC CALLS ===")
for call in pycfg_result['eval_exec_calls']:
    print(f"  Line {call.get('lineno')}: {call.get('detail')}")

print("\n=== AST EVAL/EXEC CALLS ===")
for call in ast_result['eval_exec_calls']:
    print(f"  Line {call.get('lineno')}: {call.get('detail')}")

print("\n=== PYCFG UNSAFE WRITES ===")
for uw in pycfg_result['unsafe_writes']:
    print(f"  Line {uw.get('lineno')}: {uw.get('detail')[:50]}")

print("\n=== AST UNSAFE WRITES ===")
for uw in ast_result['unsafe_writes']:
    print(f"  Line {uw.get('lineno')}: {uw.get('detail')}")