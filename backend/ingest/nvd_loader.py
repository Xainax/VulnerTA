from __future__ import annotations
import argparse, json, gzip, os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

try:
    from normalize.parse_static import CVELite  # pydantic model
    USE_PYDANTIC = True
except Exception:  # fallback if import path not set yet
    @dataclass
    class CVELite:  # minimal stand-in
        cve_id: str
        summary: Optional[str] = None
        cwe_ids: List[str] = None
        cvss_v3: Optional[float] = None
    USE_PYDANTIC = False


def _iter_paths(src: Union[str, Path]) -> Iterable[Path]:
    """Yield json or json.gz files from a file or directory."""
    p = Path(src)
    if p.is_file():
        yield p
    else:
        for f in p.rglob("*"):
            if f.suffix in (".json",) or f.suffixes[-2:] == [".json", ".gz"] or f.suffix == ".gz":
                yield f


def _open_json(path: Path) -> dict:
    if path.suffix == ".gz" or path.suffixes[-2:] == [".json", ".gz"]:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _first_english_description(cve_obj: dict) -> Optional[str]:
    # NVD 2.0: cve.descriptions = [{lang, value}, ...]
    descs = ((cve_obj or {}).get("descriptions") or [])
    for d in descs:
        if (d.get("lang") or "").lower() == "en":
            return d.get("value")
    # fallback to first
    return descs[0]["value"] if descs else None


def _extract_cwe_ids(cve_obj: dict) -> List[str]:
    # NVD 2.0: cve.weaknesses = [{description:[{value:"CWE-79"}]}]
    out: List[str] = []
    for w in (cve_obj or {}).get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = d.get("value")
            if v and "CWE-" in v:
                out.append(v)
    # de-dup while preserving order
    seen = set()
    uniq = []
    for x in out:
        if x not in seen:
            uniq.append(x)
            seen.add(x)
    return uniq


def _extract_cvss_v3(cve_obj: dict) -> Optional[float]:
    # Common places (NVD 2.0). Try v3.1, then v3.0; fall back to None.
    metrics = (cve_obj or {}).get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            data = (arr[0] or {}).get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def _cvelite_from_cve(cve_block: dict) -> Optional[CVELite]:
    """
    Accept one 'vulnerabilities[i].cve' block from NVD 2.0 feeds and map to CVELite.
    """
    cve = cve_block or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
    summary = _first_english_description(cve)
    cwe_ids = _extract_cwe_ids(cve)
    cvss = _extract_cvss_v3(cve)

    if USE_PYDANTIC:
        return CVELite(cve_id=cve_id, summary=summary, cwe_ids=cwe_ids, cvss_v3=cvss)
    else:
        return CVELite(cve_id=cve_id, summary=summary, cwe_ids=cwe_ids, cvss_v3=cvss)


def load_nvd_snapshot(src: Union[str, Path]) -> List[CVELite]:
    """
    Load one or more NVD JSON feed files (2.0 format), return list of CVELite.
    Supports .json and .json.gz files; 'src' may be a file or a directory.
    """
    out: List[CVELite] = []
    for path in _iter_paths(src):
        data = _open_json(path)

        # NVD 2.0 top-level can be 'vulnerabilities': [{cve:{...}}, ...]
        vulns = data.get("vulnerabilities") or []
        for item in vulns:
            cve_block = item.get("cve")
            c = _cvelite_from_cve(cve_block)
            if c:
                out.append(c)

        # Some historical dumps use 'CVE_Items' (1.1-like) — optional fallback
        if not vulns and "CVE_Items" in data:
            for item in data["CVE_Items"]:
                # Minimal back-compat mapping (best-effort)
                meta = ((item or {}).get("cve") or {}).get("CVE_data_meta") or {}
                cve_id = meta.get("ID")
                if not cve_id:
                    continue
                # Description
                dnodes = (((item or {}).get("cve") or {}).get("description") or {}).get("description_data") or []
                summary = None
                for d in dnodes:
                    if (d.get("lang") or "").lower() == "en":
                        summary = d.get("value"); break
                # Weakness/CWE
                cwe_ids = []
                for prob in (((item or {}).get("cve") or {}).get("problemtype") or {}).get("problemtype_data") or []:
                    for d in prob.get("description") or []:
                        v = d.get("value")
                        if v and "CWE-" in v:
                            cwe_ids.append(v)
                # CVSS v3 (if present)
                impact = (item.get("impact") or {})
                cvss_v3 = None
                for key in ("baseMetricV3",):
                    node = impact.get(key) or {}
                    meta3 = node.get("cvssV3") or {}
                    score = meta3.get("baseScore")
                    if isinstance(score, (int, float)):
                        cvss_v3 = float(score); break

                if USE_PYDANTIC:
                    out.append(CVELite(cve_id=cve_id, summary=summary, cwe_ids=cwe_ids, cvss_v3=cvss_v3))
                else:
                    out.append(CVELite(cve_id=cve_id, summary=summary, cwe_ids=cwe_ids, cvss_v3=cvss_v3))
    return out


def build_indexes(cves: List[CVELite]) -> Tuple[Dict[str, CVELite], Dict[str, List[CVELite]]]:
    """Return (by_cve_id, by_cwe) indexes."""
    by_cve: Dict[str, CVELite] = {}
    by_cwe: Dict[str, List[CVELite]] = {}
    for c in cves:
        key = c.cve_id
        if key and key not in by_cve:
            by_cve[key] = c
        for w in (c.cwe_ids or []):
            by_cwe.setdefault(w, []).append(c)
    return by_cve, by_cwe


def save_cache(cache_path: Union[str, Path], cves: List[CVELite]) -> Path:
    """Write a compact JSON cache to disk."""
    cache = Path(cache_path)
    cache.parent.mkdir(parents=True, exist_ok=True)

    # Pydantic model → dict, dataclass → dict (both supported)
    def to_dict(x: CVELite) -> dict:
        if USE_PYDANTIC and hasattr(x, "model_dump"):
            return x.model_dump()
        return asdict(x)

    payload = [to_dict(c) for c in cves]
    cache.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return cache


def load_cache(cache_path: Union[str, Path]) -> List[CVELite]:
    """Load previously saved cache into CVELite objects."""
    p = Path(cache_path)
    data = json.loads(p.read_text(encoding="utf-8"))
    out: List[CVELite] = []
    for d in data:
        if USE_PYDANTIC:
            out.append(CVELite(**d))
        else:
            out.append(CVELite(**d))
    return out


def lookup_by_cve(by_cve: Dict[str, CVELite], cve_id: str) -> Optional[CVELite]:
    return by_cve.get(cve_id)


def lookup_by_cwe(by_cwe: Dict[str, List[CVELite]], cwe_id: str, limit: int = 20) -> List[CVELite]:
    return (by_cwe.get(cwe_id) or [])[:limit]


def main():
    ap = argparse.ArgumentParser(description="Load NVD JSON (local snapshot) and build a CVE cache")
    ap.add_argument("--src", required=True, help="Path to NVD feed file or directory (json or json.gz)")
    ap.add_argument("--cache", default="data/nvd.json", help="Where to write the compact cache")
    ap.add_argument("--min", type=int, default=500, help="Minimum CVE count to consider success")
    ap.add_argument("--print-sample", action="store_true", help="Print a few records for sanity check")
    args = ap.parse_args()

    cves = load_nvd_snapshot(args.src)
    print(f"Loaded {len(cves)} CVEs from {args.src}")
    if len(cves) < args.min:
        print(f"⚠️  Warning: fewer than {args.min} CVEs — supply more NVD files for a fuller cache.")

    cache_path = save_cache(args.cache, cves)
    print(f"Wrote cache → {cache_path}")

    by_cve, by_cwe = build_indexes(cves)
    # quick probe
    some = next((cv for cv in cves if (cv.cwe_ids or [])), None)
    if some:
        sample_cwe = some.cwe_ids[0]
        print(f"Example lookup: {some.cve_id} (by cve) and CWE {sample_cwe} → {len(lookup_by_cwe(by_cwe, sample_cwe))} matches")

    if args.print_sample:
        print(json.dumps([ (cves[0].__dict__ if not USE_PYDANTIC else cves[0].model_dump()) ], indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
