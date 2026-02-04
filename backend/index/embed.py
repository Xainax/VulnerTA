# index/embed.py
from __future__ import annotations
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple
import numpy as np

@dataclass
class EmbeddingResult:
    vectors: np.ndarray  # shape: (n, d)
    model: str
    dim: int


def embed_texts(texts: List[str], prefer_openai: bool = True) -> EmbeddingResult:
    """
    Returns vectors as float32 numpy array.
    Chooses OpenAI embeddings if configured; otherwise TF-IDF fallback.
    """
    if prefer_openai and os.getenv("OPENAI_API_KEY"):
        return _embed_openai(texts)
    return _embed_local_st(texts)


def _embed_openai(texts: List[str]) -> EmbeddingResult:
    # OpenAI Python SDK (newer versions)
    from openai import OpenAI
    client = OpenAI()

    model = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-large")
    # Batch in chunks to avoid request limits
    batch_size = int(os.getenv("EMBED_BATCH_SIZE", "64"))

    vecs: List[List[float]] = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i : i + batch_size]
        resp = client.embeddings.create(model=model, input=batch)
        # Keep ordering
        for item in resp.data:
            vecs.append(item.embedding)

    arr = np.array(vecs, dtype=np.float32)
    return EmbeddingResult(vectors=arr, model=model, dim=arr.shape[1])


def _embed_local_st(texts: List[str]) -> EmbeddingResult:
    from sentence_transformers import SentenceTransformer
    model_name = os.getenv("LOCAL_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    m = SentenceTransformer(model_name)
    vecs = m.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
    vecs = vecs.astype(np.float32)
    return EmbeddingResult(vectors=vecs, model=model_name, dim=vecs.shape[1])

