from __future__ import annotations
from typing import List, Optional, Dict, Any
from enum import Enum
from pathlib import Path
import json

from pydantic import BaseModel, Field, model_validator


# ---------- Enums ----------

class ToolName(str, Enum):
    bandit = "bandit"
    semgrep = "semgrep"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    info = "info"
    unknown = "unknown"


class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    unknown = "unknown"


# ---------- Core models ----------

class Location(BaseModel):
    file_path: str
    line_start: int
    line_end: int


class ToolMeta(BaseModel):
    tool: ToolName
    rule_id: str = Field(..., description="Bandit test_id or Semgrep check_id")
    rule_name: Optional[str] = None
    severity: Severity = Severity.unknown
    confidence: Confidence = Confidence.unknown
    tags: List[str] = []


class CWERef(BaseModel):
    cwe_ids: List[str] = []  # e.g., ["CWE-94", "CWE-95"]


class CVELite(BaseModel):
    cve_id: str
    summary: Optional[str] = None
    cwe_ids: List[str] = []
    cvss_v3: Optional[float] = None


class Finding(BaseModel):
    # make id optional so we can omit it when constructing
    id: Optional[str] = None
    meta: ToolMeta
    location: Location
    message: Optional[str] = None
    cwe: CWERef = Field(default_factory=CWERef)
    related_cves: List[CVELite] = []

    @model_validator(mode="after")
    def _set_id_if_missing(self):
        if not self.id:
            self.id = f"{self.meta.tool.value}:{self.meta.rule_id}:{self.location.file_path}:{self.location.line_start}-{self.location.line_end}"
        return self


# ---------- Helpers: normalization ----------

def _norm_severity(value: Optional[str]) -> Severity:
    if not value:
        return Severity.unknown
    v = value.strip().lower()
    if v in {"critical"}:  # Semgrep sometimes has "ERROR"/"WARNING" in older outputs
        return Severity.high
    if v in {"error", "high"}:  # map semgrep "ERROR" to high
        return Severity.high
    if v in {"warning", "medium"}:
        return Severity.medium
    if v in {"info", "low"}:
        return Severity.low
    return Severity.unknown


def _norm_confidence(value: Optional[str]) -> Confidence:
    if not value:
        return Confidence.unknown
    v = value.strip().lower()
    if v in {"high"}:
        return Confidence.high
    if v in {"medium"}:
        return Confidence.medium
    if v in {"low"}:
        return Confidence.low
    return Confidence.unknown


# ---------- Bandit parser ----------

def parse_bandit_json(path: str | Path) -> List[Finding]:
    """
    Bandit JSON schema (abridged):
      {
        "results": [
          {
            "filename": "app.py",
            "issue_text": "...",
            "issue_severity": "MEDIUM",
            "issue_confidence": "HIGH",
            "issue_cwe": {"id": "CWE-94", "link": "..."} (optional),
            "test_id": "B307",
            "test_name": "eval",
            "line_number": 12,
            "line_range": [12, 13]
          }
        ]
      }
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    results = data.get("results", []) or []
    findings: List[Finding] = []
    for r in results:
        file_path = r.get("filename", "")
        start = int(r.get("line_number") or (r.get("line_range", [1])[0]))
        end = int((r.get("line_range") or [start])[-1])
        sev = _norm_severity(r.get("issue_severity"))
        conf = _norm_confidence(r.get("issue_confidence"))
        rule_id = r.get("test_id") or "UNKNOWN"
        rule_name = r.get("test_name")
        message = r.get("issue_text")

        cwe_ids: List[str] = []
        issue_cwe = r.get("issue_cwe")
        if isinstance(issue_cwe, dict):
            cwe_id = issue_cwe.get("id")
            if cwe_id:
                s = str(cwe_id)
                if s.isdigit():
                    s = f"CWE-{s}"
                cwe_ids.append(s)

        finding = Finding(
            meta=ToolMeta(
                tool=ToolName.bandit,
                rule_id=rule_id,
                rule_name=rule_name,
                severity=sev,
                confidence=conf,
                tags=[t for t in (rule_id, rule_name) if t],
            ),
            location=Location(file_path=file_path, line_start=start, line_end=end),
            message=message,
            cwe=CWERef(cwe_ids=cwe_ids),
        )
        findings.append(finding)
    return findings


# ---------- Semgrep parser ----------

def parse_semgrep_json(path: str | Path) -> List[Finding]:
    """
    Semgrep JSON schema (abridged):
      {
        "results": [
          {
            "check_id": "python.lang.security.audit.dangerous-eval",
            "path": "app.py",
            "start": {"line": 10, "col": 5},
            "end":   {"line": 12, "col": 1},
            "extra": {
              "message": "...",
              "severity": "ERROR" | "WARNING" | "INFO" | "LOW"/"MEDIUM"/"HIGH",
              "metadata": {
                "cwe": ["CWE-94"], "cwe2021-top25": true, ...
              }
            }
          }
        ]
      }
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    results = data.get("results", []) or []
    findings: List[Finding] = []
    for r in results:
        check_id = r.get("check_id") or "UNKNOWN"
        file_path = r.get("path", "")
        start_line = int(((r.get("start") or {}).get("line")) or 1)
        end_line = int(((r.get("end") or {}).get("line")) or start_line)

        extra = r.get("extra") or {}
        message = extra.get("message")
        sev = _norm_severity(extra.get("severity"))
        # Semgrep has no explicit confidence; leave unknown
        cwe_ids: List[str] = []
        md = extra.get("metadata") or {}
        # "cwe" can be list[str] or str
        if "cwe" in md:
            cwe_val = md["cwe"]
            if isinstance(cwe_val, list):
                cwe_ids.extend([str(x) for x in cwe_val if x])
            elif isinstance(cwe_val, str):
                cwe_ids.append(cwe_val)

        finding = Finding(
            meta=ToolMeta(
                tool=ToolName.semgrep,
                rule_id=check_id,
                rule_name=None,
                severity=sev,
                confidence=Confidence.unknown,
                tags=[check_id],
            ),
            location=Location(file_path=file_path, line_start=start_line, line_end=end_line),
            message=message,
            cwe=CWERef(cwe_ids=cwe_ids),
        )
        findings.append(finding)
    return findings


# ---------- CLI convenience (manual checks) ----------

def to_dicts(findings: List[Finding]) -> List[Dict[str, Any]]:
    return [f.model_dump() for f in findings]


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Parse Bandit/Semgrep JSON into unified Finding[]")
    ap.add_argument("--bandit", type=str, help="path to bandit.json")
    ap.add_argument("--semgrep", type=str, help="path to semgrep.json")
    args = ap.parse_args()

    if args.bandit:
        fs = parse_bandit_json(args.bandit)
        print(json.dumps(to_dicts(fs)[:3], indent=2))
    if args.semgrep:
        fs = parse_semgrep_json(args.semgrep)
        print(json.dumps(to_dicts(fs)[:3], indent=2))
