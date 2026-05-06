# RAG-Pipeline-VulnerTra
RAG Pipeline For VulnerTA

## How to Run
For testing purposes, using advanced-security-demo repository:
https://github.com/advanced-security-demo/demo-python

## .env
```ps1
OPENAI_API_KEY="insert OpenAI API key here" 
OPENAI_CHAT_MODEL="gpt-4o-mini" 
INDEX_DIR="local_index"
```

### Ingest
```ps1
python -m ingest.ingest_repo `
  --repo <github-repository-link> `
  --sha main `
  --out artifacts
```

### Normalize
```ps1
python -m normalize.parse_static --bandit artifacts/bandit.json --semgrep artifacts/semgrep.json
```

### Load NVD (Static Snapshot)
```ps1
python -m ingest.nvd_loader --src data/raw --cache data/nvd.json --min 500 --print-sample
```

### Load NVD API (Full Harvest)
```ps1
python -m ingest.nvd_api_loader --mode all --out-cache data/nvd_api.json
```

### Incremental NVD Harvest (Last 7 Days)
Example dates:
```ps1
python -m ingest.nvd_api_loader --mode incremental --last-mod-start "2025-02-10T00:00:00" --last-mod-end "2025-02-17T00:00:00" --out-cache data/nvd_inc.json
```

### Link NVD to Bandit and Semgrep
```ps1
python -m normalize.linker --bandit artifacts/bandit.json --semgrep artifacts/semgrep.json --cve-cache data/nvd_api.json
```

### Chunk repository code
```ps1
python -m index.chunker --repo-root repo_checkout --print-n 2
```

### Build the index
```ps1
python -m index.store_faiss index `
  --repo-root repo_checkout `
  --bandit artifacts/bandit.json `
  --semgrep artifacts/semgrep.json `
  --cve-cache data/nvd_api.json `
  --out-dir local_index
```

### Run the API
```ps1
cd backend
uvicorn retriever.app:app --host 127.0.0.1 --port 8000
```
Go to: http://127.0.0.1:8000/docs

Sample Search API Call, No Auth Needed:  
```json
{
  "query": "hardcoded password github token",
  "top_k": 5
}
```

For all vulnerabilities:
```json
{
  "query": ""
}
```

Sample Answer API Call, No Auth Needed:
```json
{
  "question": "Bandit flagged B307 eval usage. Explain the risk and suggest a minimal patch diff.",
  "top_k": 5
}
```

### To Run Tests
```ps1
py -m pytest -q
```

### Remove Artifacts
```ps1
Remove-Item -Recurse -Force artifacts, repo_checkout
```