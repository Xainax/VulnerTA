# index/store_faiss.py
from __future__ import annotations
import argparse, json, os
from pathlib import Path
from typing import Any, Dict, List, Tuple
import numpy as np

import duckdb

from index.embed import embed_texts
from index.chunker import build_chunks_for_repo
from normalize.parse_static import parse_bandit_json, parse_semgrep_json
from normalize.linker import link_findings


def _ensure_dir(p: Path):
    p.parent.mkdir(parents=True, exist_ok=True)


def save_duckdb(db_path: Path, chunks: List[dict]):
    """
    Store:
      - doc_id (primary)
      - text
      - meta JSON
    """
    con = duckdb.connect(str(db_path))
    con.execute("""
        CREATE TABLE IF NOT EXISTS docs (
            doc_id VARCHAR PRIMARY KEY,
            text VARCHAR,
            meta JSON
        )
    """)
    # Upsert
    for c in chunks:
        con.execute(
            "INSERT OR REPLACE INTO docs VALUES (?, ?, ?)",
            [c["doc_id"], c["text"], json.dumps(c["meta"])],
        )
    con.close()


def load_duckdb(db_path: Path, doc_ids: List[str]) -> List[dict]:
    con = duckdb.connect(str(db_path), read_only=True)
    placeholders = ",".join(["?"] * len(doc_ids))
    rows = con.execute(
        f"SELECT doc_id, text, meta FROM docs WHERE doc_id IN ({placeholders})",
        doc_ids,
    ).fetchall()
    con.close()
    out = []
    for doc_id, text, meta in rows:
        out.append({"doc_id": doc_id, "text": text, "meta": json.loads(meta)})
    return out


def build_faiss_index(vectors: np.ndarray) -> "faiss.Index":
    import faiss

    dim = vectors.shape[1]
    # Cosine similarity via inner product on normalized vectors
    faiss.normalize_L2(vectors)
    index = faiss.IndexFlatIP(dim)
    index.add(vectors)
    return index


def index_pipeline(
    repo_root: str,
    bandit_path: str,
    semgrep_path: str,
    cve_cache: str,
    out_dir: str,
    include_code_chunks: bool = True,
):
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) Parse findings
    findings = []
    if Path(bandit_path).exists():
        findings += parse_bandit_json(bandit_path)
    if Path(semgrep_path).exists():
        findings += parse_semgrep_json(semgrep_path)

    # 2) Link findings to CWE/CVE
    findings, ctr = link_findings(findings, cve_cache_path=cve_cache)
    print("Linker counters:", ctr.to_prom_like())

    # 3) Build chunks (Day 5)
    chunks = build_chunks_for_repo(repo_root, findings, halo_lines=4)

    # If your Day 5 returns only retrieval chunks, you can optionally append code chunks:
    # (Best fix is to return all_code_chunks + retrieval_chunks in Day 5)
    # Here we accept whatever build_chunks_for_repo returns.

    print(f"Built {len(chunks)} chunks total")

    # 4) Embed
    texts = [c.text for c in chunks]
    emb = embed_texts(texts, prefer_openai=True)
    vectors = emb.vectors
    print(f"Embedded: {vectors.shape} using {emb.model}")

    # 5) Build FAISS and persist
    import faiss
    index = build_faiss_index(vectors)

    faiss_path = out_dir / "index.faiss"
    faiss.write_index(index, str(faiss_path))

    # 6) Persist docs+meta in DuckDB
    db_path = out_dir / "meta.duckdb"
    rows = [{"doc_id": c.doc_id, "text": c.text, "meta": c.meta} for c in chunks]
    save_duckdb(db_path, rows)

    # 7) Store FAISS integer ID → doc_id mapping
    id_map = {i: rows[i]["doc_id"] for i in range(len(rows))}
    (out_dir / "id_map.json").write_text(json.dumps(id_map, indent=2), encoding="utf-8")

    # 8) Save embedding config
    (out_dir / "embedding.json").write_text(
        json.dumps({"model": emb.model, "dim": emb.dim, "count": int(vectors.shape[0])}, indent=2),
        encoding="utf-8",
    )

    print(f"✅ Wrote FAISS index: {faiss_path}")
    print(f"✅ Wrote DuckDB store: {db_path}")
    print(f"✅ Wrote id map: {out_dir / 'id_map.json'}")


def search(
    out_dir: str,
    query: str,
    top_k: int = 5,
):
    out_dir = Path(out_dir).resolve()
    faiss_path = out_dir / "index.faiss"
    db_path = out_dir / "meta.duckdb"
    id_map_path = out_dir / "id_map.json"

    import faiss
    index = faiss.read_index(str(faiss_path))

    id_map = json.loads(id_map_path.read_text(encoding="utf-8"))
    # Embed query
    emb = embed_texts([query], prefer_openai=True)
    q = emb.vectors
    faiss.normalize_L2(q)

    scores, idxs = index.search(q, top_k)
    idxs = idxs[0].tolist()
    scores = scores[0].tolist()

    doc_ids = [id_map[str(i)] if isinstance(id_map, dict) and str(i) in id_map else id_map.get(i) for i in idxs]
    docs = load_duckdb(db_path, doc_ids)

    # Keep same order as faiss results
    doc_by_id = {d["doc_id"]: d for d in docs}
    ordered = [doc_by_id[d] for d in doc_ids if d in doc_by_id]

    for rank, (doc_id, score) in enumerate(zip(doc_ids, scores), start=1):
        d = doc_by_id.get(doc_id)
        if not d:
            continue
        meta = d["meta"]
        print("=" * 90)
        print(f"Rank {rank}  score={score:.4f}  doc_id={doc_id}")
        print(f"file={meta.get('file_path')}  rule={meta.get('rule_id')}  cwes={meta.get('cwe_ids')}")
        print(d["text"][:1200])


def main():
    ap = argparse.ArgumentParser(description="Build/search local FAISS index for RAG pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_index = sub.add_parser("index", help="Build index from repo_checkout + artifacts")
    p_index.add_argument("--repo-root", default="repo_checkout")
    p_index.add_argument("--bandit", default="artifacts/bandit.json")
    p_index.add_argument("--semgrep", default="artifacts/semgrep.json")
    p_index.add_argument("--cve-cache", default="data/nvd.json")
    p_index.add_argument("--out-dir", default="local_index")

    p_search = sub.add_parser("search", help="Search the index")
    p_search.add_argument("--out-dir", default="local_index")
    p_search.add_argument("--query", required=True)
    p_search.add_argument("--top-k", type=int, default=5)

    args = ap.parse_args()

    if args.cmd == "index":
        index_pipeline(args.repo_root, args.bandit, args.semgrep, args.cve_cache, args.out_dir)
    elif args.cmd == "search":
        search(args.out_dir, args.query, top_k=args.top_k)


if __name__ == "__main__":
    main()
