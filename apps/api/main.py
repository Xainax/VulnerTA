from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from apps.api.github import fetch_python_files
from dotenv import load_dotenv
from pathlib import Path
import os

# our AST-based analyzer
from backend.analysis.ast_analysis import analyze_files

# Load .env from the project root (two levels up from apps/api/main.py)
root_dir = Path(__file__).resolve().parents[2]
dotenv_path = root_dir / ".env"
if not dotenv_path.exists():
    raise FileNotFoundError(f".env file not found at {dotenv_path}")

load_dotenv(dotenv_path=dotenv_path)

app = FastAPI(title="VulnerTA")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    repo_link: str

@app.get("/")
def root():
    return {"status": "VulnerTA backend running"}

@app.post("/scan")
def scan_repo(req: ScanRequest):
    # Validate GitHub repo URL
    if "github.com" not in req.repo_link:
        raise HTTPException(status_code=400, detail="Invalid GitHub repo URL")

    # Fetch token at request time
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise HTTPException(status_code=500, detail="Missing GITHUB_TOKEN")

    # Fetch Python files (including content) from repo
    try:
        files = fetch_python_files(req.repo_link, token, fetch_content=True)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # run a lightweight AST analysis over all sources
    analysis = analyze_files(files)

    return {
        "repo": req.repo_link,
        "python_files": len(files),
        # return only first 50 file metadata to keep response small
        "files": [{"path": f["path"], "size": f.get("size", 0)} for f in files[:50]],
        "analysis": analysis,
    }

@app.get("/health")
def health():
    return {"status": "ok"}
