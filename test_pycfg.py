from backend.analysis.pycfg_analysis import analyze_code
import json

# Read the test file
with open('test_vuln_file.py', 'r') as f:
    code = f.read()

# Analyze with PyCFG
result = analyze_code(code, 'test_vuln_file.py')
print('PyCFG Analysis Results:')
print(json.dumps(result['counts'], indent=2))
print(f'Risk score: {result["risk"]}')

# Also test AST analysis for comparison
from backend.analysis.ast_analysis import analyze_code as ast_analyze
ast_result = ast_analyze(code, 'test_vuln_file.py')
print('\nAST Analysis Results:')
print(json.dumps(ast_result['counts'], indent=2))
print(f'Risk score: {ast_result["risk"]}')