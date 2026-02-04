# RAG-Pipeline-VulnerTra
RAG Pipeline For VulnerTA

## How to Run
For testing purposes, using advanced-security-demo repository:
https://github.com/advanced-security-demo/demo-python

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

## To Run Tests
```ps1
py -m pytest -q
```

### Remove Artifacts
```ps1
Remove-Item -Recurse -Force artifacts, repo_checkout
```