# index/chunker.py
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from normalize.parse_static import Finding, ToolName


@dataclass
class Chunk:
    doc_id: str
    text: str
    meta: Dict[str, Any]


# -------------------------
# Utilities
# -------------------------

def _read_lines(path: Path) -> List[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()

def _stable_id(*parts: str) -> str:
    h = hashlib.sha1("::".join(parts).encode("utf-8")).hexdigest()[:16]
    return h

def _norm_path(p: str) -> str:
    # normalize Windows paths to a consistent style
    return p.replace("\\", "/")

def _safe_int(x, default=1) -> int:
    try:
        return int(x)
    except Exception:
        return default


# -------------------------
# Python code chunking
# -------------------------

def _node_end_lineno(node: ast.AST) -> Optional[int]:
    # Python 3.8+ has end_lineno; if missing, None
    return getattr(node, "end_lineno", None)

def _collect_def_spans(tree: ast.AST) -> List[Tuple[str, int, int]]:
    """
    Return list of spans: (kind:name, start_line, end_line)
    kind:name is one of "func:<name>", "class:<name>"
    """
    spans = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = getattr(n, "lineno", None)
            end = _node_end_lineno(n)
            if start and end:
                spans.append((f"func:{n.name}", start, end))
        elif isinstance(n, ast.ClassDef):
            start = getattr(n, "lineno", None)
            end = _node_end_lineno(n)
            if start and end:
                spans.append((f"class:{n.name}", start, end))
    # sort by start line
    spans.sort(key=lambda x: (x[1], x[2]))
    return spans

def chunk_python_file(
    file_path: Path,
    repo_root: Path,
    halo_lines: int = 4,
    min_lines: int = 5,
) -> List[Chunk]:
    """
    Chunks a Python file into function/class blocks + optional module-level chunk.
    Adds a 'halo' of surrounding lines for readability.
    """
    rel_path = _norm_path(str(file_path.relative_to(repo_root)))
    lines = _read_lines(file_path)
    src = "\n".join(lines)

    try:
        tree = ast.parse(src)
    except SyntaxError:
        # If file can't parse, fallback to one whole-file chunk
        start, end = 1, max(1, len(lines))
        return [_make_chunk(repo_root, rel_path, "module:unparsed", lines, start, end)]

    spans = _collect_def_spans(tree)
    chunks: List[Chunk] = []

    # Always add a module-level chunk if there's meaningful top-level content
    if len(lines) >= min_lines:
        chunks.append(_make_chunk(repo_root, rel_path, "module", lines, 1, min(len(lines), 200)))

    for kind_name, s, e in spans:
        start = max(1, s - halo_lines)
        end = min(len(lines), e + halo_lines)
        if (end - start + 1) < min_lines:
            continue
        chunks.append(_make_chunk(repo_root, rel_path, kind_name, lines, start, end))

    return chunks

def _make_chunk(repo_root: Path, rel_path: str, symbol: str, lines: List[str], start: int, end: int) -> Chunk:
    snippet = "\n".join(lines[start - 1 : end])
    doc_id = _stable_id(rel_path, symbol, str(start), str(end))
    meta = {
        "file_path": rel_path,
        "symbol": symbol,
        "line_start": start,
        "line_end": end,
    }
    # keep "text" clean; retrieval builder will add richer context
    return Chunk(doc_id=doc_id, text=snippet, meta=meta)


# -------------------------
# Finding → Chunk matching
# -------------------------

def pick_chunk_for_finding(chunks: List[Chunk], finding: Finding) -> Optional[Chunk]:
    """
    Choose the best chunk in the same file whose span covers the finding line.
    Prefer smallest covering chunk (more specific than module chunk).
    """
    fpath = _norm_path(finding.location.file_path)
    fline = _safe_int(finding.location.line_start, 1)

    same_file = [c for c in chunks if _norm_path(c.meta.get("file_path", "")) == fpath]
    if not same_file:
        return None

    covering = []
    for c in same_file:
        s = _safe_int(c.meta.get("line_start"), 1)
        e = _safe_int(c.meta.get("line_end"), 1)
        if s <= fline <= e:
            covering.append((e - s, c))  # smaller span is better

    if covering:
        covering.sort(key=lambda x: x[0])
        return covering[0][1]

    # fallback: nearest chunk by distance
    def dist(c: Chunk) -> int:
        s = _safe_int(c.meta.get("line_start"), 1)
        e = _safe_int(c.meta.get("line_end"), 1)
        if fline < s:
            return s - fline
        if fline > e:
            return fline - e
        return 0

    same_file.sort(key=dist)
    return same_file[0]


# -------------------------
# Retrieval text builder
# -------------------------

def build_retrieval_text(finding: Finding, code_chunk: Optional[Chunk]) -> Tuple[str, Dict[str, Any]]:
    """
    Build a single text blob the vector DB can embed.
    Include: finding message + tool + rule + severity + code snippet + CWE/CVE blurbs.
    """
    # Code header
    loc = finding.location
    header = f"FILE: {finding.location.file_path}  LINES: {loc.line_start}-{loc.line_end}"

    tool = finding.meta.tool.value if hasattr(finding.meta.tool, "value") else str(finding.meta.tool)
    rule = finding.meta.rule_id
    sev = finding.meta.severity

    finding_block = (
        f"TOOL: {tool}\n"
        f"RULE: {rule}\n"
        f"SEVERITY: {sev}\n"
        f"MESSAGE: {finding.message or ''}\n"
    )

    cwe_block = ""
    if finding.cwe.cwe_ids:
        cwe_block = "CWES: " + ", ".join(finding.cwe.cwe_ids) + "\n"

    cve_block = ""
    if finding.related_cves:
        # keep it short to avoid huge contexts
        lines = []
        for c in finding.related_cves[:5]:
            summary = (c.summary or "").strip().replace("\n", " ")
            if len(summary) > 240:
                summary = summary[:240] + "…"
            score = f"{c.cvss_v3}" if c.cvss_v3 is not None else "n/a"
            lines.append(f"- {c.cve_id} (CVSS {score}): {summary}")
        cve_block = "RELATED_CVES:\n" + "\n".join(lines) + "\n"

    code_block = ""
    meta = {}
    if code_chunk:
        meta = dict(code_chunk.meta)
        code_block = "CODE_SNIPPET:\n" + code_chunk.text + "\n"

    text = "\n".join([header, finding_block, cwe_block, cve_block, code_block]).strip()

    # Build meta for indexing/filtering
    out_meta = {
        "finding_id": finding.id,
        "tool": tool,
        "rule_id": rule,
        "severity": str(sev),
        "file_path": _norm_path(loc.file_path),
        "line_start": loc.line_start,
        "line_end": loc.line_end,
        "cwe_ids": finding.cwe.cwe_ids,
        "cve_ids": [c.cve_id for c in (finding.related_cves or [])],
    }
    # attach chunk info if present
    if meta:
        out_meta.update(
            {
                "chunk_id": code_chunk.doc_id,
                "symbol": meta.get("symbol"),
                "chunk_line_start": meta.get("line_start"),
                "chunk_line_end": meta.get("line_end"),
            }
        )
    return text, out_meta


# -------------------------
# End-to-end: repo → chunks
# -------------------------

def build_chunks_for_repo(
    repo_root: str | Path,
    findings: List[Finding],
    halo_lines: int = 4,
) -> List[Chunk]:
    """
    1) Chunk all *.py files under repo_root.
    2) For each finding, attach the best chunk and build a retrieval-text Chunk.
    Returns a list of chunks ready for embedding/indexing.
    """
    repo_root = Path(repo_root).resolve()
    all_code_chunks: List[Chunk] = []

    for pyfile in repo_root.rglob("*.py"):
        # ignore venvs or large vendor dirs if you want:
        if "/.venv/" in _norm_path(str(pyfile)) or "/venv/" in _norm_path(str(pyfile)):
            continue
        all_code_chunks.extend(chunk_python_file(pyfile, repo_root, halo_lines=halo_lines))

    # Create retrieval chunks (one per finding) using attached code chunk
    retrieval_chunks: List[Chunk] = []
    for f in findings:
        code_chunk = pick_chunk_for_finding(all_code_chunks, f)
        text, meta = build_retrieval_text(f, code_chunk)

        # doc_id derived from finding id for stable upserts
        doc_id = _stable_id("finding", f.id)
        retrieval_chunks.append(Chunk(doc_id=doc_id, text=text, meta=meta))

    return all_code_chunks + retrieval_chunks
    # return retrieval_chunks


# -------------------------
# CLI sanity check
# -------------------------
if __name__ == "__main__":
    import argparse, json
    from normalize.parse_static import parse_bandit_json, parse_semgrep_json
    from normalize.linker import link_findings

    ap = argparse.ArgumentParser(description="Chunk repo and build retrieval chunks for findings")
    ap.add_argument("--repo-root", default="repo_checkout")
    ap.add_argument("--bandit", default="artifacts/bandit.json")
    ap.add_argument("--semgrep", default="artifacts/semgrep.json")
    ap.add_argument("--cve-cache", default="data/nvd.json")
    ap.add_argument("--halo", type=int, default=4)
    ap.add_argument("--print-n", type=int, default=2)
    args = ap.parse_args()

    fs = []
    if Path(args.bandit).exists():
        fs += parse_bandit_json(args.bandit)
    if Path(args.semgrep).exists():
        fs += parse_semgrep_json(args.semgrep)

    fs, _ = link_findings(fs, cve_cache_path=args.cve_cache)
    chunks = build_chunks_for_repo(args.repo_root, fs, halo_lines=args.halo)

    print(f"Built {len(chunks)} retrieval chunks (one per finding).")
    for c in chunks[: args.print_n]:
        print("=" * 80)
        print(json.dumps({"doc_id": c.doc_id, "meta": c.meta}, indent=2))
        print(c.text[:1200])
