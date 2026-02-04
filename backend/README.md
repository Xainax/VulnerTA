# RAG-Pipeline-VulnerTra
RAG Pipeline For VulnerTA

## How to Run
For testing purposes, using advanced-security-demo repository:
https://github.com/advanced-security-demo/demo-python

## .env
```ps1
OPENAI_API_KEY="insert OpenAI API key here"  
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

### Link NVD to Bandit and Semgrep
```ps1
python -m normalize.linker --bandit artifacts/bandit.json --semgrep artifacts/semgrep.json --cve-cache data/nvd.json
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
  --cve-cache data/nvd.json `
  --out-dir local_index
```

### Run the API
```ps1
uvicorn retriever.app:app --host 127.0.0.1 --port 8000
```

Sample API Call, No Auth Needed:  
```json
{
  "query": "hardcoded password github token",
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