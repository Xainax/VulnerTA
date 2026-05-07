# retriever/llm_orchestrator.py
from __future__ import annotations

import os
import re
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests


# -------------------------
# Models
# -------------------------
@dataclass
class Citation:
    doc_id: str
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    rule_id: Optional[str]
    cwe_ids: List[str]
    cve_ids: List[str]


@dataclass
class AnswerResult:
    answer: str
    citations: List[Citation]
    used_context_doc_ids: List[str]


# -------------------------
# Prompting
# -------------------------
SYSTEM_PROMPT = """You are a security code assistant.
You are given two sources: the current repository static analysis summary and retrieved vulnerability knowledge.
Your job:
1) Base your answer on the static analysis summary first.
2) Use retrieved context only if it explicitly confirms or explains the same file, line number, or issue from the analysis summary.
3) Do not invent file paths, line numbers, or CVE IDs that are not present in the analysis summary.
4) If retrieved context appears unrelated to the scanned repository, ignore it and keep the report grounded in the analysis summary.
5) Suggest a minimal, safe patch (prefer a unified diff).
If information is missing, say what you assume and what you cannot verify."""


USER_TEMPLATE = """User question:
{question}

Static analysis summary (AST + PyCFG):
{analysis_context}

Retrieved context (use for citations):
{context}

Requirements:
- Create a vulnerability report based on the AST and PyCFG static analysis findings.
- Base the report on the analysis summary first; do not use retrieved context to invent the source file or line number.
- Use the exact file names and line numbers from the analysis context when describing the reported issue.
- If retrieved context does not explicitly match the scanned file, ignore it.
- Explain the security issue, likely root cause, affected code patterns, and risk level.
- Recommend a minimal fix and, if possible, provide a patch diff.
- Provide citations as a list of doc_ids you used.
- If the issue looks like eval/exec/code injection, prefer safer parsing, whitelisting, or ast.literal_eval where appropriate.
"""

PATCH_SYSTEM_PROMPT = """You are a security code assistant. The user is asking for a patch for a specific vulnerability.
Your response must have exactly two parts:
1. Explanation: 2–4 sentences explaining what the vulnerability is and how your patch fixes it (why it is safe).
2. Patch: A minimal unified diff in a ```diff code block. Include any new imports. Do not put the patch outside the code block."""
PATCH_USER_TEMPLATE = """User request:
{question}

Static analysis summary (AST + PyCFG):
{analysis_context}

Retrieved context (use for citations):
{context}

Respond with: (1) A short explanation of the vulnerability and how the patch fixes it, then (2) the patch in a ```diff code block."""


def format_context(hits: List[Dict[str, Any]], max_chars: int = 20000) -> Tuple[str, List[Citation]]:
    """
    Build a compact context block for the LLM and a structured citation list.
    """
    parts = []
    citations: List[Citation] = []
    used = 0

    for i, h in enumerate(hits, start=1):
        meta = h.get("meta") or {}
        text = h.get("text") or ""
        doc_id = h.get("doc_id")

        # structured citation
        citations.append(
            Citation(
                doc_id=doc_id,
                file_path=meta.get("file_path"),
                line_start=meta.get("line_start"),
                line_end=meta.get("line_end"),
                rule_id=meta.get("rule_id"),
                cwe_ids=meta.get("cwe_ids") or [],
                cve_ids=meta.get("cve_ids") or [],
            )
        )

        block = (
            f"[{i}] doc_id={doc_id}\n"
            f"file={meta.get('file_path')} lines={meta.get('line_start')}-{meta.get('line_end')} "
            f"rule={meta.get('rule_id')} cwes={meta.get('cwe_ids')} cves={meta.get('cve_ids')}\n"
            f"{text}\n"
        )
        if used + len(block) > max_chars:
            break
        parts.append(block)
        used += len(block)

    return "\n---\n".join(parts), citations


def redact_secrets(s: str) -> str:
    if not s:
        return s
    # redacts GitHub fine-grained tokens
    s = re.sub(r"github_pat_[A-Za-z0-9_]+", "[REDACTED_GITHUB_PAT]", s)
    # add more patterns later (AWS keys etc.)
    return s


# -------------------------
# LLM call
# -------------------------
def call_openai_chat(system: str, user: str) -> str:
    from openai import OpenAI
    client = OpenAI()

    model = os.getenv("OPENAI_CHAT_MODEL", "gpt-4o-mini")
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.2,
    )
    return resp.choices[0].message.content or ""


def local_fallback_answer(question: str, hits: List[Dict[str, Any]]) -> str:
    """
    Offline fallback: heuristic answer that still returns something useful.
    Not a real LLM, but meets “pipeline works” needs.
    """
    # Try detect eval issue
    joined = " ".join((h.get("text") or "") for h in hits).lower()
    if " eval" in joined or "dangerous eval" in joined or "B307".lower() in joined:
        return (
            "Explanation: The code appears to use eval(), which can execute attacker-controlled input.\n"
            "Risk: If user input reaches eval(), an attacker may run arbitrary Python code.\n"
            "Recommended fix: Avoid eval(). If you only need to parse literals, use ast.literal_eval; "
            "otherwise implement a whitelist parser.\n"
            "Minimal diff patch (example):\n"
            "```diff\n"
            "- result = eval(user_input)\n"
            "+ import ast\n"
            "+ result = ast.literal_eval(user_input)\n"
            "```\n"
            "Citations: (see provided context doc_ids)\n"
        )
    return (
        "Explanation: Based on retrieved context, this finding indicates a potential security issue.\n"
        "Recommended fix: Apply least-privilege, input validation, and safer APIs.\n"
        "Minimal diff patch: (insufficient code context to produce an exact patch)\n"
        "Citations: (see provided context doc_ids)\n"
    )


def local_fallback_patch(question: str, hits: List[Dict[str, Any]]) -> str:
    """Offline fallback for /patch: response shaped as explanation then ```diff``` block."""
    joined = " ".join((h.get("text") or "") for h in hits).lower()
    if " eval" in joined or "dangerous eval" in joined or "b307" in joined:
        return (
            "Explanation: The code uses eval(), which can execute attacker-controlled input. "
            "Replacing it with ast.literal_eval (for literals only) or a whitelist parser removes that risk.\n\n"
            "```diff\n"
            "- result = eval(user_input)\n"
            "+ import ast\n"
            "+ result = ast.literal_eval(user_input)\n"
            "```\n"
        )
    return (
        "Explanation: Based on the retrieved context, this finding indicates a potential security issue. "
        "```diff\n\n"
        "```\n"
    )

def debug_hits(label: str, hits: List[Dict[str, Any]]) -> None:
    if os.getenv("RAG_DEBUG", "0") != "1":
        return

    print(f"\n[{label}] retrieved hits: {len(hits)}")
    for h in hits:
        meta = h.get("meta") or {}
        print(
            f"- doc_id={h.get('doc_id')} "
            f"file={meta.get('file_path')} "
            f"lines={meta.get('line_start')}-{meta.get('line_end')} "
            f"rule={meta.get('rule_id')} "
            f"score={h.get('score')}"
        )

def norm_path_for_key(p: str) -> str:
    return (p or "").replace("\\", "/").lstrip("./")

def dedupe_hits(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []

    for h in hits:
        meta = h.get("meta") or {}

        key = (
            norm_path_for_key(meta.get("file_path")),
            meta.get("line_start"),
            meta.get("line_end"),
        )

        if key in seen:
            continue

        seen.add(key)
        out.append(h)

    return out

def orchestrate_answer(
    question: str,
    retriever_url: str,
    top_k: int = 50,
    filters: Optional[Dict[str, Any]] = None,
    analysis_context: Optional[str] = None,
) -> AnswerResult:
    """
    1) Call /search
    2) Build prompt
    3) Call LLM
    4) Return answer + structured citations
    """
    # 1) Retrieve
    payload = {
        "query": question,
        "top_k": top_k,
        "dense_k": 50,
        "sparse_k": 50,
        "alpha": 0.6,
        "filters": filters or None,
    }
    r = requests.post(f"{retriever_url}/search", json=payload, timeout=60)
    r.raise_for_status()
    hits = r.json().get("hits") or []

    debug_hits("RAW", hits)

    hits = dedupe_hits(hits)

    debug_hits("DEDUPED", hits)

    context_str, citations = format_context(hits)

    # 2) Format context
    context_str, citations = format_context(hits)
    context_str = redact_secrets(context_str)
    analysis_context = analysis_context or "No additional static analysis summary provided."

    # 3) Prompt
    user_prompt = USER_TEMPLATE.format(
        question=question,
        analysis_context=analysis_context,
        context=context_str,
    )

    # 4) LLM
    if os.getenv("OPENAI_API_KEY"):
        answer = call_openai_chat(SYSTEM_PROMPT, user_prompt)
    else:
        answer = local_fallback_answer(question, hits)

    answer = redact_secrets(answer)

    used_doc_ids = [c.doc_id for c in citations]
    return AnswerResult(answer=answer, citations=citations, used_context_doc_ids=used_doc_ids)


def orchestrate_patch(
    question: str,
    retriever_url: str,
    top_k: int = 50,
    filters: Optional[Dict[str, Any]] = None,
    analysis_context: Optional[str] = None,
) -> AnswerResult:
    """
    For /patch only: retrieve, prompt for explanation + ```diff``` patch, return answer + citations.
    Response is shaped as explanation text then a ```diff code block (parsed by the patch endpoint).
    """
    payload = {
        "query": question,
        "top_k": top_k,
        "dense_k": 25,
        "sparse_k": 25,
        "alpha": 0.6,
        "filters": filters or None,
    }
    r = requests.post(f"{retriever_url}/search", json=payload, timeout=15)
    r.raise_for_status()
    hits = r.json().get("hits") or []

    debug_hits("RAW", hits)

    hits = dedupe_hits(hits)

    debug_hits("DEDUPED", hits)

    context_str, citations = format_context(hits)
    context_str = redact_secrets(context_str)
    analysis_context = analysis_context or "No additional static analysis summary provided."
    user_prompt = PATCH_USER_TEMPLATE.format(
        question=question,
        analysis_context=analysis_context,
        context=context_str,
    )

    if os.getenv("OPENAI_API_KEY"):
        answer = call_openai_chat(PATCH_SYSTEM_PROMPT, user_prompt)
    else:
        answer = local_fallback_patch(question, hits)

    answer = redact_secrets(answer)
    return AnswerResult(answer=answer, citations=citations, used_context_doc_ids=[c.doc_id for c in citations])
