from pathlib import Path
import json
from normalize.parse_static import (
    parse_bandit_json,
    parse_semgrep_json,
    Finding,
    ToolName,
    Severity,
    Confidence,
)

def write(tmp_path: Path, name: str, payload: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_bandit_happy_path(tmp_path):
    sample = {
        "results": [
            {
                "filename": "app.py",
                "issue_text": "Use of eval is insecure",
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": "CWE-94"},
                "test_id": "B307",
                "test_name": "eval",
                "line_number": 12,
                "line_range": [12, 12],
            }
        ]
    }
    path = write(tmp_path, "bandit.json", sample)
    findings = parse_bandit_json(path)
    assert len(findings) == 1
    f: Finding = findings[0]
    assert f.meta.tool == ToolName.bandit
    assert f.meta.rule_id == "B307"
    assert f.meta.severity == Severity.medium
    assert f.meta.confidence == Confidence.high
    assert f.location.file_path == "app.py"
    assert f.location.line_start == 12
    assert f.cwe.cwe_ids == ["CWE-94"]
    assert f.id.startswith("bandit:B307:app.py:12-12")


def test_bandit_missing_fields_defaults(tmp_path):
    sample = {"results": [{"filename": "x.py", "test_id": "B999"}]}
    path = write(tmp_path, "bandit_min.json", sample)
    f = parse_bandit_json(path)[0]
    assert f.meta.severity == Severity.unknown
    assert f.meta.confidence == Confidence.unknown
    assert f.location.line_start >= 1
    assert f.cwe.cwe_ids == []


def test_semgrep_happy_path(tmp_path):
    sample = {
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-eval",
                "path": "main.py",
                "start": {"line": 3},
                "end": {"line": 5},
                "extra": {
                    "message": "dangerous eval",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-94", "CWE-95"]},
                },
            }
        ]
    }
    path = write(tmp_path, "semgrep.json", sample)
    fs = parse_semgrep_json(path)
    assert len(fs) == 1
    f: Finding = fs[0]
    assert f.meta.tool == ToolName.semgrep
    assert f.meta.rule_id == "python.lang.security.audit.dangerous-eval"
    assert f.meta.severity == Severity.high
    assert f.location.file_path == "main.py"
    assert f.location.line_start == 3
    assert f.location.line_end == 5
    assert "CWE-94" in f.cwe.cwe_ids


def test_semgrep_missing_metadata(tmp_path):
    sample = {"results": [{"check_id": "x.y.rule", "path": "x.py", "start": {"line": 1}}]}
    path = write(tmp_path, "semgrep_min.json", sample)
    f = parse_semgrep_json(path)[0]
    assert f.meta.severity in {Severity.unknown, Severity.low, Severity.medium, Severity.high}
    assert f.cwe.cwe_ids == []
    assert f.location.line_start == 1
    assert f.location.line_end == 1
