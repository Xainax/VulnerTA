import requests
import json

# Test scan endpoint on port 8000
print('Testing /scan on port 8000...')
try:
    resp = requests.post('http://127.0.0.1:8000/scan', json={'repo_link': 'https://github.com/psf/requests'}, timeout=30)
    print(f'Status: {resp.status_code}')
    if resp.status_code == 200:
        data = resp.json()
        print(f'Files analyzed: {data.get("python_files", "N/A")}')
        print('Response keys:', list(data.keys()))
        if 'analysis' in data:
            print('Analysis keys:', list(data['analysis'].keys()))
    else:
        print('Response text:', resp.text[:200])
except Exception as e:
    print(f'Error: {e}')