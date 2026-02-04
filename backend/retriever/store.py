# retriever/store.py
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List
import duckdb

def load_doc_by_ids(db_path: str, doc_ids: List[str]) -> List[Dict[str, Any]]:
    con = duckdb.connect(db_path, read_only=True)
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

def iter_all_docs(db_path: str) -> List[Dict[str, Any]]:
    con = duckdb.connect(db_path, read_only=True)
    rows = con.execute("SELECT doc_id, text, meta FROM docs").fetchall()
    con.close()
    out = []
    for doc_id, text, meta in rows:
        out.append({"doc_id": doc_id, "text": text, "meta": json.loads(meta)})
    return out
