# retriever/app.py
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends, FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

import duckdb
from rank_bm25 import BM25Okapi

import faiss

from index.embed import embed_texts  # uses OpenAI or local fallback
from retriever.store import load_doc_by_ids, iter_all_docs
from retriever.llm_orchestrator import orchestrate_answer


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
    repo: Optional[str] = None  # only if you store it in meta later


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


# -------------------------
# App + global state
# -------------------------
app = FastAPI(title="VulnerTA Retriever API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow all for dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATE: Dict[str, Any] = {}


@app.on_event("startup")
def startup():
    # Load FAISS
    if not Path(FAISS_PATH).exists():
        raise RuntimeError(f"FAISS index not found at {FAISS_PATH}. Run Day 6 indexing first.")
    index = faiss.read_index(FAISS_PATH)

    # Load id map (faiss_id -> doc_id)
    id_map = json.loads(Path(ID_MAP_PATH).read_text(encoding="utf-8"))

    # Load docs for BM25
    docs = iter_all_docs(DB_PATH)
    # Tokenize for BM25
    tokenized = [_tokenize_for_bm25(d["text"]) for d in docs]
    bm25 = BM25Okapi(tokenized)

    STATE["faiss"] = index
    STATE["id_map"] = id_map
    STATE["bm25"] = bm25
    STATE["bm25_docs"] = docs
    print(f"✅ Loaded FAISS dim={index.d} docs={len(docs)}")


@app.get("/health")
def health():
    return {"ok": True, "index_dir": str(INDEX_DIR)}


# -------------------------
# Core search helpers
# -------------------------
def _tokenize_for_bm25(text: str) -> List[str]:
    # Simple tokenization; you can improve later
    return [t for t in text.lower().replace("\n", " ").split(" ") if t]


def _apply_filters(docs: List[Dict[str, Any]], flt: Optional[SearchFilters]) -> List[Dict[str, Any]]:
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
    q = emb.vectors.astype(np.float32)
    faiss.normalize_L2(q)

    # Dim check (prevents your previous d mismatch issues)
    if q.shape[1] != index.d:
        raise HTTPException(
            status_code=500,
            detail=f"Embedding dim mismatch: query dim={q.shape[1]} vs index dim={index.d}. Rebuild index with same embedder.",
        )

    scores, idxs = index.search(q, k)
    idxs = idxs[0].tolist()
    scores = scores[0].tolist()

    out: List[Tuple[str, float]] = []
    for faiss_id, score in zip(idxs, scores):
        # id_map keys may be strings depending on how you wrote json
        doc_id = id_map.get(str(faiss_id)) if isinstance(id_map, dict) else None
        if doc_id:
            out.append((doc_id, float(score)))
    return out


def sparse_search(query: str, k: int) -> List[Tuple[str, float]]:
    """Return list of (doc_id, score) using BM25 over all docs."""
    bm25: BM25Okapi = STATE["bm25"]
    docs: List[Dict[str, Any]] = STATE["bm25_docs"]

    toks = _tokenize_for_bm25(query)
    scores = bm25.get_scores(toks)  # ndarray length = len(docs)

    # Take top-k
    idxs = np.argsort(scores)[::-1][:k]
    out = [(docs[i]["doc_id"], float(scores[i])) for i in idxs]
    return out


def hybrid_merge(
    dense: List[Tuple[str, float]],
    sparse: List[Tuple[str, float]],
    alpha: float,
    top_k: int,
) -> List[Tuple[str, float]]:
    """
    Merge by doc_id. Normalize each score list to [0,1] then combine:
      score = alpha * dense_norm + (1-alpha) * sparse_norm
    """
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


# -------------------------
# Route
# -------------------------
@app.post("/search", response_model=SearchResponse)
def search_endpoint(req: SearchRequest, _auth=Depends(require_bearer)):
    # Retrieve candidates
    dense_hits = dense_search(req.query, req.dense_k)
    sparse_hits = sparse_search(req.query, req.sparse_k)

    merged = hybrid_merge(dense_hits, sparse_hits, alpha=req.alpha, top_k=req.top_k)

    # Load docs
    doc_ids = [doc_id for doc_id, _ in merged]
    docs = load_doc_by_ids(DB_PATH, doc_ids)
    docs = _apply_filters(docs, req.filters)

    # Re-score after filtering (keep original merged score when possible)
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

    # Ensure we still return top_k after filtering
    hits.sort(key=lambda h: h.score, reverse=True)
    hits = hits[: req.top_k]

    return SearchResponse(query=req.query, hits=hits)


# -------------------------
# Route
# -------------------------
@app.post("/answer", response_model=AnswerResponse)
def answer_endpoint(req: AnswerRequest, _auth=Depends(require_bearer)):
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