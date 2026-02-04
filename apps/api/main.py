from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from apps.api.github import fetch_python_files
from dotenv import load_dotenv
from pathlib import Path
import os

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

    # Fetch Python files from repo
    try:
        files = fetch_python_files(req.repo_link, token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "repo": req.repo_link,
        "python_files": len(files),
        "files": files[:50]
    }

@app.get("/health")
def health():
    return {"status": "ok"}
