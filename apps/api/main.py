from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from apps.api.github import fetch_python_files  
from dotenv import load_dotenv
import os

load_dotenv()
token = os.getenv("GITHUB_TOKEN")

app = FastAPI(title="VulnerTA")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    repo_link: str

@app.post("/scan")
def scan_repo(req: ScanRequest):
    if "github.com" not in req.repo_link:
        raise HTTPException(status_code=400, detail="Invalid GitHub repo URL")

    if not token:
        raise HTTPException(status_code=500, detail="Missing GITHUB_TOKEN")

    files = fetch_python_files(req.repo_link, token)
    return {
        "repo": req.repo_link,
        "python_files": len(files),
        "files": files[:50]
    }

@app.get("/health")
def health():
    return {"status": "ok"}