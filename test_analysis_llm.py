import requests
import json

# Test scan endpoint
print('=== Testing /scan endpoint ===')
scan_resp = requests.post('http://127.0.0.1:8000/scan', json={'repo_link': 'https://github.com/psf/requests'})
if scan_resp.ok:
    data = scan_resp.json()
    print(f'Files analyzed: {data["python_files"]}')
    print(f'AST analysis counts: {data["analysis"]["ast"]["counts"]}')
    print(f'PyCFG analysis counts: {data["analysis"]["pycfg"]["counts"]}')

    # Extract analysis context for LLM
    ast_counts = data['analysis']['ast']['counts']
    pycfg_counts = data['analysis']['pycfg']['counts']
    analysis_context = f'AST analysis counts: {json.dumps(ast_counts)}\nPyCFG analysis counts: {json.dumps(pycfg_counts)}'
    print(f'\nAnalysis context: {analysis_context}')

    # Test LLM with analysis context
    print('\n=== Testing /answer endpoint with analysis context ===')
    answer_resp = requests.post('http://127.0.0.1:8000/answer', json={
        'question': 'What are the main security issues found in this codebase?',
        'top_k': 3,
        'analysis_context': analysis_context
    })

    if answer_resp.ok:
        answer_data = answer_resp.json()
        print('LLM Answer:')
        print(answer_data['answer'][:500] + '...' if len(answer_data['answer']) > 500 else answer_data['answer'])
        print(f'Citations: {len(answer_data["citations"])}')
    else:
        print(f'Answer failed: {answer_resp.status_code}')

else:
    print(f'Scan failed: {scan_resp.status_code}')