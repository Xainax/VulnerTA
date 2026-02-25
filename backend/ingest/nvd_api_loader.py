from __future__ import annotations
import os
import time
import json
import argparse
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter, Retry

# reuse CVELite and helpers
try:
    from ingest.nvd_loader import _cvelite_from_cve, save_cache, build_indexes, CVELite  # noqa
    USE_SHARED = True
except Exception:
    # minimal local stand-ins
    from ingest.nvd_loader import CVELite, _cvelite_from_cve, save_cache, build_indexes  # try again
    USE_SHARED = True  # if import fails adjust accordingly


BASE = os.getenv("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0/")
API_KEY = os.getenv("NVD_API_KEY", "")  # to raise rate limits, get an API key


def _requests_session_with_retry(total_retries: int = 5, backoff: float = 1.0) -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=total_retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    return s


def _build_headers() -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    # NVD docs accept either header 'apiKey' or 'X-Api-Key'
    if API_KEY:
        headers["apiKey"] = API_KEY
        headers["X-Api-Key"] = API_KEY
    return headers


def fetch_page(session: requests.Session, params: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch a single page, raise for HTTP errors, return parsed JSON."""
    headers = _build_headers()
    resp = session.get(BASE, headers=headers, params=params, timeout=30)
    if resp.status_code == 429:
        # Backoff according to Retry-After if present
        ra = resp.headers.get("Retry-After")
        wait = int(ra) if ra and ra.isdigit() else 5
        time.sleep(wait)
        resp = session.get(BASE, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def harvest_all(
    out_cache: str = "data/nvd_api.json",
    results_per_page: int = 5000,
    max_pages: Optional[int] = None,
    start_index: int = 0,
) -> List[CVELite]:
    """
    Harvest the entire CVE space (paginated).
    results_per_page: up to service limits
    max_pages: stop early for testing (None => run until totalResults).
    """
    session = _requests_session_with_retry()
    params = {"startIndex": start_index, "resultsPerPage": results_per_page}

    all_cves: List[CVELite] = []
    page = 0

    while True:
        page += 1
        params["startIndex"] = start_index + (page - 1) * results_per_page
        print(f"Fetching page {page} (startIndex={params['startIndex']}) ...")
        data = fetch_page(session, params)

        vulns = data.get("vulnerabilities") or []
        for item in vulns:
            cve_block = item.get("cve")
            c = _cvelite_from_cve(cve_block)
            if c:
                all_cves.append(c)

        total = int(data.get("totalResults", 0) or 0)
        fetched = params["startIndex"] + len(vulns)
        print(f"  fetched {len(vulns)} vulns; totalResults={total}; accumulated={len(all_cves)}")

        # stop conditions
        if max_pages and page >= max_pages:
            break
        if fetched >= total or len(vulns) == 0:
            break

        # polite pause to avoid throttling
        time.sleep(0.2)

    # persist cache
    save_cache(out_cache, all_cves)
    return all_cves


def harvest_incremental(
    out_cache: str = "data/nvd_api_incremental.json",
    last_mod_start: Optional[str] = None,
    last_mod_end: Optional[str] = None,
    results_per_page: int = 2000,
) -> List[CVELite]:
    """
    Use lastModStartDate / lastModEndDate to fetch only recently modified CVEs.
    Date format: ISO 8601 like '2024-01-01T00:00:00:000 UTC-00:00' or simplified '2024-01-01T00:00:00'
    If last_mod_start is None, default to 30 days ago.
    """
    if not last_mod_end:
        last_mod_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    if not last_mod_start:
        last_dt = datetime.utcnow() - timedelta(days=30)
        last_mod_start = last_dt.strftime("%Y-%m-%dT%H:%M:%S")

    session = _requests_session_with_retry()
    params = {
        "resultsPerPage": results_per_page,
        "lastModStartDate": last_mod_start,
        "lastModEndDate": last_mod_end,
        "startIndex": 0,
    }

    all_cves: List[CVELite] = []
    page = 0
    while True:
        page += 1
        params["startIndex"] = (page - 1) * results_per_page
        print(f"Fetching incremental page {page} startIndex={params['startIndex']} ...")
        data = fetch_page(session, params)

        vulns = data.get("vulnerabilities") or []
        for item in vulns:
            cve_block = item.get("cve")
            c = _cvelite_from_cve(cve_block)
            if c:
                all_cves.append(c)

        total = int(data.get("totalResults", 0) or 0)
        fetched = params["startIndex"] + len(vulns)
        print(f"  fetched {len(vulns)} vulns; totalResults={total}; accumulated={len(all_cves)}")

        if fetched >= total or len(vulns) == 0:
            break

        time.sleep(0.2)

    save_cache(out_cache, all_cves)
    return all_cves


def main():
    ap = argparse.ArgumentParser(description="Harvest NVD CVEs from NVD API v2.0")
    ap.add_argument("--out-cache", default="data/nvd_api.json")
    ap.add_argument("--mode", choices=("all", "incremental"), default="all")
    ap.add_argument("--results-per-page", type=int, default=2000)
    ap.add_argument("--max-pages", type=int, default=0, help="For testing: max pages to fetch (0 = unlimited)")
    ap.add_argument("--start-index", type=int, default=0, help="startIndex for full harvest")
    ap.add_argument("--last-mod-start", type=str, default=None, help="ISO datetime for incremental start")
    ap.add_argument("--last-mod-end", type=str, default=None, help="ISO datetime for incremental end")
    args = ap.parse_args()

    # Basic warnings / guidance
    if not API_KEY:
        print("Warning: NVD API key not set. Set NVD_API_KEY to increase limits.")

    if args.mode == "all":
        max_pages = args.max_pages if args.max_pages > 0 else None
        cves = harvest_all(out_cache=args.out_cache, results_per_page=args.results_per_page, max_pages=max_pages, start_index=args.start_index)
    else:
        cves = harvest_incremental(out_cache=args.out_cache, last_mod_start=args.last_mod_start, last_mod_end=args.last_mod_end, results_per_page=args.results_per_page)

    print(f"Harvested {len(cves)} CVEs, saved to {args.out_cache}")
    by_cve, by_cwe = build_indexes(cves)
    print(f"Built indexes: cves={len(by_cve)} cwes={len(by_cwe)}")
    print("Example lookup:", next(iter(by_cve.keys())) if by_cve else "(none)")

if __name__ == "__main__":
    main()