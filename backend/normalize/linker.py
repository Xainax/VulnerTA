# normalize/linker.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import json

from normalize.parse_static import Finding, CVELite, ToolName

# -------------------------
# Seed rule → CWE mappings
# -------------------------
# Keep this small for v0; expand over time.
BANDIT_RULE_TO_CWES: Dict[str, List[str]] = {
    "B307": ["CWE-94", "CWE-95"],   # eval / code injection
    "B303": ["CWE-327"],            # md5/weak crypto
    "B324": ["CWE-295"],            # SSL/TLS cert validation disabled
    "B501": ["CWE-22"],             # requests without timeout → often treated as reliability; optional
}

# Semgrep rules vary by config pack; do best-effort by check_id prefix or exact IDs you see.
SEMGREP_RULE_TO_CWES: Dict[str, List[str]] = {
    # Example check_id (adjust to what your semgrep config produces)
    "python.lang.security.audit.dangerous-eval": ["CWE-94", "CWE-95"],
    "python.lang.security.injection.command-injection": ["CWE-78"],
}

# -------------------------
# Counters (simple in-proc)
# -------------------------
@dataclass
class LinkerCounters:
    cwe_matches_seed_map: int = 0        # rule → CWE mapping
    cwe_matches_tool_metadata: int = 0   # CWE already present from Bandit/Semgrep
    cwe_matches_none: int = 0             # no CWE found
    cve_links_created: int = 0

    def to_prom_like(self):
        return {
            'linker.cwe_matches_total{method="seed_map"}': self.cwe_matches_seed_map,
            'linker.cwe_matches_total{method="tool_metadata"}': self.cwe_matches_tool_metadata,
            'linker.cwe_matches_total{method="none"}': self.cwe_matches_none,
            'linker.cve_links_created_total': self.cve_links_created,
        }


# -------------------------
# CVE cache helpers
# -------------------------
def load_cve_cache(cache_path: str | Path = "data/nvd.json") -> List[CVELite]:
    p = Path(cache_path)
    data = json.loads(p.read_text(encoding="utf-8"))
    return [CVELite(**d) for d in data]

def build_cwe_to_cves(cves: List[CVELite]) -> Dict[str, List[CVELite]]:
    by_cwe: Dict[str, List[CVELite]] = {}
    for c in cves:
        for w in (c.cwe_ids or []):
            by_cwe.setdefault(w, []).append(c)
    return by_cwe


# -------------------------
# Linking logic
# -------------------------
def rule_to_cwes(f: Finding) -> List[str]:
    """Return CWE IDs from seeded mapping based on tool+rule_id."""
    rid = f.meta.rule_id
    if f.meta.tool == ToolName.bandit:
        return BANDIT_RULE_TO_CWES.get(rid, [])
    if f.meta.tool == ToolName.semgrep:
        return SEMGREP_RULE_TO_CWES.get(rid, [])
    return []

def merge_cwes(existing: List[str], new: List[str]) -> List[str]:
    seen = set(existing)
    out = list(existing)
    for x in new:
        if x and x not in seen:
            out.append(x)
            seen.add(x)
    return out

def attach_related_cves(
    cwe_to_cves: Dict[str, List[CVELite]],
    cwe_ids: List[str],
    limit_per_cwe: int = 5,
    max_total: int = 15,
) -> List[CVELite]:
    """Join CVEs by CWE (simple v0 join)."""
    out: List[CVELite] = []
    seen = set()
    for cwe in cwe_ids:
        for cve in (cwe_to_cves.get(cwe) or [])[:limit_per_cwe]:
            if cve.cve_id not in seen:
                out.append(cve)
                seen.add(cve.cve_id)
            if len(out) >= max_total:
                return out
    return out


def link_findings(
    findings: List[Finding],
    cve_cache_path: str | Path = "data/nvd.json",
    counters: Optional[LinkerCounters] = None,
) -> Tuple[List[Finding], LinkerCounters]:
    """
    Enrich each Finding with:
      - cwe_ids (seed map + existing tool metadata)
      - related_cves (join by CWE against cached NVD)
    """
    counters = counters or LinkerCounters()
    cves = load_cve_cache(cve_cache_path)
    cwe_to_cves = build_cwe_to_cves(cves)

    for f in findings:
        # 1) Seed CWEs from mapping
        seeded = rule_to_cwes(f)

        # 2) Merge with any CWE already present from tool metadata
        before = list(f.cwe.cwe_ids or [])
        merged = merge_cwes(before, seeded)
        f.cwe.cwe_ids = merged

        if seeded:
            counters.cwe_matches_seed_map += 1
        elif before:
            counters.cwe_matches_tool_metadata += 1
        else:
            counters.cwe_matches_none += 1

        # 3) Attach related CVEs if we have CWE(s)
        if merged:
            rel = attach_related_cves(cwe_to_cves, merged)
            f.related_cves = rel
            if rel:
                counters.cve_links_created += 1

    return findings, counters


def coverage(findings: List[Finding]) -> float:
    """% findings that have at least one CWE or one CVE link."""
    if not findings:
        return 0.0
    linked = 0
    for f in findings:
        if (f.cwe.cwe_ids and len(f.cwe.cwe_ids) > 0) or (f.related_cves and len(f.related_cves) > 0):
            linked += 1
    return linked / len(findings)


# -------------------------
# CLI for quick manual run
# -------------------------
if __name__ == "__main__":
    import argparse
    from normalize.parse_static import parse_bandit_json, parse_semgrep_json

    ap = argparse.ArgumentParser(description="Link Findings to CWE and related CVEs (v0)")
    ap.add_argument("--bandit", default="artifacts/bandit.json")
    ap.add_argument("--semgrep", default="artifacts/semgrep.json")
    ap.add_argument("--cve-cache", default="data/nvd.json")
    args = ap.parse_args()

    fs = []
    if Path(args.bandit).exists():
        fs += parse_bandit_json(args.bandit)
    if Path(args.semgrep).exists():
        fs += parse_semgrep_json(args.semgrep)

    linked, ctr = link_findings(fs, cve_cache_path=args.cve_cache)
    cov = coverage(linked)
    print(f"Linked coverage: {cov:.1%} ({int(cov*len(linked))}/{len(linked)})")
    print(json.dumps(ctr.to_prom_like(), indent=2))
    # Print first 2 linked findings
    print(json.dumps([linked[0].model_dump(), linked[1].model_dump()] if len(linked) >= 2 else [linked[0].model_dump()], indent=2, ensure_ascii=False))
