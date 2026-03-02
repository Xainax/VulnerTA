# backend/retriever/app.py
from __future__ import annotations

# ensure necessary directories are on sys.path so sibling packages
# (`apps` and the backend "namespace" such as `index`) are importable when
# running uvicorn from either the backend directory or the workspace root.
import sys
from pathlib import Path
# workspace root is two levels above this file (backend/retriever -> backend -> root)
root_dir = Path(__file__).resolve().parents[2]
backend_dir = root_dir / "backend"
for p in (str(backend_dir), str(root_dir)):
    if p not in sys.path:
        sys.path.insert(0, p)

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends, FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

import duckdb
from rank_bm25 import BM25Okapi

import faiss

from index.embed import embed_texts
from retriever.store import load_doc_by_ids, iter_all_docs
from retriever.llm_orchestrator import orchestrate_answer, orchestrate_patch
from .oauth_handler import router as oauth_router


# -------------------------
# Config
# -------------------------
INDEX_DIR = Path(os.getenv("INDEX_DIR", "local_index")).resolve()
FAISS_PATH = str(INDEX_DIR / "index.faiss")
DB_PATH = str(INDEX_DIR / "meta.duckdb")
ID_MAP_PATH = str(INDEX_DIR / "id_map.json")
AUTH_TOKEN = os.getenv("RETRIEVER_TOKEN", "")  # set to require auth


# -------------------------
# Auth dependency
# -------------------------
def require_bearer(authorization: Optional[str] = Header(default=None)):
    if not AUTH_TOKEN:
        return True  # auth disabled
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if token != AUTH_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")
    return True


# -------------------------
# Request/Response models
# -------------------------
class SearchFilters(BaseModel):
    rule_id: Optional[str] = None
    file_path: Optional[str] = None
    cwe_id: Optional[str] = None
    repo: Optional[str] = None


class SearchRequest(BaseModel):
    query: str
    top_k: int = Field(default=5, ge=1, le=50)
    dense_k: int = Field(default=20, ge=1, le=200)
    sparse_k: int = Field(default=20, ge=1, le=200)
    alpha: float = Field(default=0.6, ge=0.0, le=1.0, description="Weight for dense score in hybrid merge")
    filters: Optional[SearchFilters] = None


class Hit(BaseModel):
    doc_id: str
    score: float
    text: str
    meta: Dict[str, Any]


class SearchResponse(BaseModel):
    query: str
    hits: List[Hit]


class AnswerRequest(BaseModel):
    question: str
    top_k: int = Field(default=5, ge=1, le=20)
    filters: Optional[SearchFilters] = None


class CitationOut(BaseModel):
    doc_id: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    rule_id: Optional[str] = None
    cwe_ids: List[str] = []
    cve_ids: List[str] = []


class AnswerResponse(BaseModel):
    answer: str
    citations: List[CitationOut]


class PatchRequest(BaseModel):
    rule_id: str
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: str
    vulnerability_description: Optional[str] = None
    top_k: int = Field(default=5, ge=1, le=20)
    filters: Optional[SearchFilters] = None


class PatchResponse(BaseModel):
    patch: str
    explanation: str
    citations: List[CitationOut]


class FileVulnerability(BaseModel):
    """Response model for file vulnerabilities endpoint"""
    file_path: str
    vulnerabilities: List[Hit]
    total_count: int


# -------------------------
# App + global state
# -------------------------
app = FastAPI(title="VulnerTA Retriever API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow all for dev; restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(oauth_router)

STATE: Dict[str, Any] = {}


@app.on_event("startup")
def startup():
    """Initialize FAISS index and BM25 on startup"""
    if not Path(FAISS_PATH).exists():
        raise RuntimeError(f"FAISS index not found at {FAISS_PATH}. Run indexing first.")
    
    index = faiss.read_index(FAISS_PATH)
    id_map = json.loads(Path(ID_MAP_PATH).read_text(encoding="utf-8"))
    
    docs = list(iter_all_docs(DB_PATH))
    tokenized = [_tokenize_for_bm25(d["text"]) for d in docs]
    bm25 = BM25Okapi(tokenized)

    STATE["faiss"] = index
    STATE["id_map"] = id_map
    STATE["bm25"] = bm25
    STATE["bm25_docs"] = docs
    STATE["all_docs"] = docs  # Keep all docs for filtering
    
    print(f"✅ Loaded FAISS: dim={index.d}, docs={len(docs)}")


@app.get("/health")
def health():
    """Health check endpoint"""
    return {
        "status": "ok",
        "index_dir": str(INDEX_DIR),
        "docs_loaded": len(STATE.get("bm25_docs", []))
    }

# ------------------------------------------------------------------
# Merge scan endpoint from the main API so a single uvicorn command works
# ------------------------------------------------------------------
from apps.api.main import scan_repo, ScanRequest

# re‑expose the same path and request model
@app.post("/scan")
def scan_repo_proxy(req: ScanRequest):
    # simply delegate to the original handler
    return scan_repo(req)


# -------------------------
# Core search helpers
# -------------------------
def _tokenize_for_bm25(text: str) -> List[str]:
    """Simple tokenization for BM25"""
    return [t for t in text.lower().replace("\n", " ").split(" ") if t]


def _apply_filters(docs: List[Dict[str, Any]], flt: Optional[SearchFilters]) -> List[Dict[str, Any]]:
    """Apply filters to documents"""
    if not flt:
        return docs

    def match(d: Dict[str, Any]) -> bool:
        m = d.get("meta") or {}
        if flt.rule_id and m.get("rule_id") != flt.rule_id:
            return False
        if flt.file_path and m.get("file_path") != flt.file_path:
            return False
        if flt.cwe_id:
            cwes = m.get("cwe_ids") or []
            if flt.cwe_id not in cwes:
                return False
        if flt.repo and m.get("repo") != flt.repo:
            return False
        return True

    return [d for d in docs if match(d)]


def dense_search(query: str, k: int) -> List[Tuple[str, float]]:
    """Return list of (doc_id, score) from FAISS (cosine via inner product)."""
    index: faiss.Index = STATE["faiss"]
    id_map: Dict[str, str] = STATE["id_map"]

    emb = embed_texts([query], prefer_openai=True)
    
    # Fallback to local embedder if dimension mismatch
    if emb.vectors.shape[1] != index.d:
        emb = embed_texts([query], prefer_openai=False)
    
    q = emb.vectors.astype(np.float32)
    faiss.normalize_L2(q)

    if q.shape[1] != index.d:
        raise HTTPException(
            status_code=500,
            detail=f"Embedding dim mismatch: query={q.shape[1]} vs index={index.d}",
        )

    scores, idxs = index.search(q, k)
    idxs = idxs[0].tolist()
    scores = scores[0].tolist()

    out: List[Tuple[str, float]] = []
    for faiss_id, score in zip(idxs, scores):
        doc_id = id_map.get(str(faiss_id)) if isinstance(id_map, dict) else None
        if doc_id:
            out.append((doc_id, float(score)))
    return out


def sparse_search(query: str, k: int) -> List[Tuple[str, float]]:
    """Return list of (doc_id, score) using BM25 over all docs."""
    bm25: BM25Okapi = STATE["bm25"]
    docs: List[Dict[str, Any]] = STATE["bm25_docs"]

    toks = _tokenize_for_bm25(query)
    scores = bm25.get_scores(toks)

    idxs = np.argsort(scores)[::-1][:k]
    out = [(docs[i]["doc_id"], float(scores[i])) for i in idxs]
    return out


def hybrid_merge(
    dense: List[Tuple[str, float]],
    sparse: List[Tuple[str, float]],
    alpha: float,
    top_k: int,
) -> List[Tuple[str, float]]:
    """Merge dense and sparse search results with normalization"""
    def norm_map(pairs: List[Tuple[str, float]]) -> Dict[str, float]:
        if not pairs:
            return {}
        vals = np.array([s for _, s in pairs], dtype=np.float32)
        vmin, vmax = float(vals.min()), float(vals.max())
        if vmax - vmin < 1e-9:
            return {doc: 1.0 for doc, _ in pairs}
        return {doc: float((s - vmin) / (vmax - vmin)) for doc, s in pairs}

    dn = norm_map(dense)
    sn = norm_map(sparse)

    all_ids = set(dn.keys()) | set(sn.keys())
    merged = []
    for doc_id in all_ids:
        merged_score = alpha * dn.get(doc_id, 0.0) + (1.0 - alpha) * sn.get(doc_id, 0.0)
        merged.append((doc_id, float(merged_score)))

    merged.sort(key=lambda x: x[1], reverse=True)
    return merged[:top_k]


def _parse_patch_response(answer_text: str) -> tuple[str, str]:
    """Split LLM response into explanation and patch"""
    explanation = ""
    patch = ""

    block_match = re.search(r"```(?:diff|patch)?\s*\n(.*?)```", answer_text, re.DOTALL | re.IGNORECASE)
    if block_match:
        patch_content = block_match.group(1).strip()
        patch_content = "\n".join(
            line[1:] if len(line) > 1 and line[0] == " " and line[1] in "-+" else line
            for line in patch_content.split("\n")
        )
        patch = f"```diff\n{patch_content}\n```" if patch_content else ""
        before = answer_text[: block_match.start()].strip()
        explanation = before if before else answer_text.strip()
        explanation = re.sub(r"^\s*1\.\s+", "", explanation).strip()
        explanation = re.sub(r"\s+\d+\.\s*$", "", explanation).strip()
        explanation = re.sub(r"\s*\n\s*\d+\.\s*$", "", explanation).strip()

    else:
        explanation = answer_text.strip()
        patch = ""

    if patch and not explanation:
        explanation = "See patch below."
    if not explanation and answer_text:
        explanation = answer_text.strip()

    return explanation, patch


# -------------------------
# Search endpoint
# -------------------------
@app.post("/search", response_model=SearchResponse)
def search_endpoint(req: SearchRequest, _auth=Depends(require_bearer)):
    """
    Hybrid search endpoint (dense + sparse).
    Supports filtering by rule_id, file_path, cwe_id, repo.
    """
    dense_hits = dense_search(req.query, req.dense_k)
    sparse_hits = sparse_search(req.query, req.sparse_k)
    merged = hybrid_merge(dense_hits, sparse_hits, alpha=req.alpha, top_k=req.top_k)

    doc_ids = [doc_id for doc_id, _ in merged]
    docs = load_doc_by_ids(DB_PATH, doc_ids)
    docs = _apply_filters(docs, req.filters)

    score_map = dict(merged)
    hits = []
    for d in docs:
        hits.append(
            Hit(
                doc_id=d["doc_id"],
                score=float(score_map.get(d["doc_id"], 0.0)),
                text=d["text"],
                meta=d["meta"],
            )
        )

    hits.sort(key=lambda h: h.score, reverse=True)
    hits = hits[: req.top_k]

    return SearchResponse(query=req.query, hits=hits)


# -------------------------
# File-specific vulnerabilities endpoint (for CodeViewer)
# -------------------------
@app.get("/file-vulnerabilities/{file_path:path}")
def file_vulnerabilities_endpoint(file_path: str, top_k: int = 50, _auth=Depends(require_bearer)):
    """
    Get all vulnerabilities for a specific file.
    Used by CodeViewer to highlight vulnerable lines.
    
    Example: GET /file-vulnerabilities/backend/ingest/ingest_repo.py
    """
    all_docs: List[Dict[str, Any]] = STATE.get("all_docs", [])
    
    # Filter docs by file_path
    file_docs = [
        d for d in all_docs
        if d.get("meta", {}).get("file_path") == file_path
    ]

    # Sort by line number
    file_docs.sort(key=lambda d: d.get("meta", {}).get("line_start", 0))

    # Limit results
    file_docs = file_docs[:top_k]

    hits = [
        Hit(
            doc_id=d["doc_id"],
            score=1.0,  # Fixed score for file-specific results
            text=d["text"],
            meta=d["meta"],
        )
        for d in file_docs
    ]

    return FileVulnerability(
        file_path=file_path,
        vulnerabilities=hits,
        total_count=len(file_docs)
    )


# -------------------------
# Search by file endpoint
# -------------------------
@app.post("/search-by-file")
def search_by_file_endpoint(file_path: str, top_k: int = 50, _auth=Depends(require_bearer)):
    """
    Alternative endpoint to search vulnerabilities in a specific file.
    
    POST /search-by-file?file_path=backend/ingest/ingest_repo.py&top_k=50
    """
    filters = SearchFilters(file_path=file_path)
    req = SearchRequest(query="", top_k=top_k, filters=filters)
    
    # Get all docs matching file
    all_docs: List[Dict[str, Any]] = STATE.get("all_docs", [])
    filtered_docs = _apply_filters(all_docs, filters)
    filtered_docs.sort(key=lambda d: d.get("meta", {}).get("line_start", 0))

    hits = [
        Hit(
            doc_id=d["doc_id"],
            score=1.0,
            text=d["text"],
            meta=d["meta"],
        )
        for d in filtered_docs[:top_k]
    ]

    return SearchResponse(query=f"vulnerabilities in {file_path}", hits=hits)


# -------------------------
# Answer endpoint
# -------------------------
@app.post("/answer", response_model=AnswerResponse)
def answer_endpoint(req: AnswerRequest, _auth=Depends(require_bearer)):
    """
    Explain a vulnerability using RAG + LLM.
    """
    retriever_url = os.getenv("RETRIEVER_URL", "http://127.0.0.1:8000")
    result = orchestrate_answer(
        question=req.question,
        retriever_url=retriever_url,
        top_k=req.top_k,
        filters=req.filters.model_dump() if req.filters else None,
    )
    return AnswerResponse(
        answer=result.answer,
        citations=[
            CitationOut(
                doc_id=c.doc_id,
                file_path=c.file_path,
                line_start=c.line_start,
                line_end=c.line_end,
                rule_id=c.rule_id,
                cwe_ids=c.cwe_ids,
                cve_ids=c.cve_ids,
            )
            for c in result.citations
        ],
    )


# -------------------------
# Patch endpoint
# -------------------------
@app.post("/patch", response_model=PatchResponse)
def patch_endpoint(req: PatchRequest, _auth=Depends(require_bearer)):
    """
    Generate a patch for a vulnerability using RAG + LLM.
    """
    retriever_url = os.getenv("RETRIEVER_URL", "http://127.0.0.1:8000")

    patch_question = (
        f"Generate a minimal, safe patch for this security finding.\n\n"
        f"Rule: {req.rule_id}\n"
        f"File: {req.file_path}\n"
        f"Lines: {req.line_start}-{req.line_end}\n"
        f"Vulnerable code:\n{req.code_snippet}\n"
    )
    if req.vulnerability_description:
        patch_question += f"Finding: {req.vulnerability_description}\n"

    patch_question += (
        "\nRespond in exactly two parts:\n"
        "1. Explanation: In 2–4 sentences, explain what the vulnerability is and how your patch fixes it.\n"
        "2. Patch: Provide a minimal unified diff in a ```diff code block.\n"
    )

    result = orchestrate_patch(
        question=patch_question,
        retriever_url=retriever_url,
        top_k=req.top_k,
        filters=req.filters.model_dump() if req.filters else None,
    )

    answer_text = result.answer
    explanation, patch = _parse_patch_response(answer_text)

    return PatchResponse(
        patch=patch if patch else "No patch generated",
        explanation=explanation,
        citations=[
            CitationOut(
                doc_id=c.doc_id,
                file_path=c.file_path,
                line_start=c.line_start,
                line_end=c.line_end,
                rule_id=c.rule_id,
                cwe_ids=c.cwe_ids,
                cve_ids=c.cve_ids,
            )
            for c in result.citations
        ],
    )


# -------------------------
# Additional utility endpoints
# -------------------------
@app.get("/stats")
def stats_endpoint(_auth=Depends(require_bearer)):
    """
    Get statistics about the indexed vulnerabilities.
    """
    all_docs: List[Dict[str, Any]] = STATE.get("all_docs", [])
    
    if not all_docs:
        return {"error": "No docs loaded"}

    # Count by severity
    severity_counts = {}
    for doc in all_docs:
        severity = doc.get("meta", {}).get("severity", "unknown").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Count by tool
    tool_counts = {}
    for doc in all_docs:
        tool = doc.get("meta", {}).get("tool", "unknown")
        tool_counts[tool] = tool_counts.get(tool, 0) + 1

    # Count by file
    file_counts = {}
    for doc in all_docs:
        file_path = doc.get("meta", {}).get("file_path", "unknown")
        file_counts[file_path] = file_counts.get(file_path, 0) + 1

    return {
        "total_vulnerabilities": len(all_docs),
        "by_severity": severity_counts,
        "by_tool": tool_counts,
        "by_file": dict(sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
    }


@app.get("/rules")
def list_rules_endpoint(_auth=Depends(require_bearer)):
    """
    Get all unique rule IDs in the index.
    """
    all_docs: List[Dict[str, Any]] = STATE.get("all_docs", [])
    
    rules = set()
    for doc in all_docs:
        rule_id = doc.get("meta", {}).get("rule_id")
        if rule_id:
            rules.add(rule_id)

    return {"rules": sorted(list(rules))}


@app.get("/files")
def list_files_endpoint(_auth=Depends(require_bearer)):
    """
    Get all unique files with vulnerabilities.
    """
    all_docs: List[Dict[str, Any]] = STATE.get("all_docs", [])
    
    files = {}
    for doc in all_docs:
        file_path = doc.get("meta", {}).get("file_path")
        if file_path:
            if file_path not in files:
                files[file_path] = 0
            files[file_path] += 1

    return {
        "files": sorted(
            [{"path": f, "count": c} for f, c in files.items()],
            key=lambda x: x["count"],
            reverse=True
        )
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)