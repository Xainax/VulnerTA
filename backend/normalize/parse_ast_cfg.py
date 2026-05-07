# normalize/parse_ast_cfg.py
from __future__ import annotations

from pathlib import Path
from typing import List, Dict, Any

from normalize.parse_static import (
    Finding,
    Location,
    ToolMeta,
    CWERef,
    ToolName,
    Severity,
    Confidence,
)


KIND_TO_CWE = {
    "eval_exec": ["CWE-94", "CWE-95"],
    "tainted_flow": ["CWE-74"],
    "unsafe_write": ["CWE-22", "CWE-73"],
}


def _severity_for_kind(kind: str) -> Severity:
    if kind == "tainted_flow":
        return Severity.high
    if kind == "eval_exec":
        return Severity.high
    if kind == "unsafe_write":
        return Severity.medium
    return Severity.unknown


def _make_finding(
    tool: str,
    file_path: str,
    kind: str,
    lineno: int,
    message: str,
    detail: Dict[str, Any],
) -> Finding:
    rule_id = f"{tool}:{kind}"

    return Finding(
        meta=ToolMeta(
            tool=ToolName(tool), 
            rule_id=rule_id,
            rule_name=kind,
            severity=_severity_for_kind(kind),
            confidence=Confidence.medium,
            tags=[tool, kind],
        ),
        location=Location(
            file_path=file_path,
            line_start=lineno or 1,
            line_end=lineno or 1,
        ),
        message=message,
        cwe=CWERef(cwe_ids=KIND_TO_CWE.get(kind, [])),
    )


def parse_ast_analysis_result(result: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    for file_result in result.get("files", []):
        file_path = file_result.get("file", "")

        for item in file_result.get("flows", []):
            findings.append(
                _make_finding(
                    "ast_analysis",
                    file_path,
                    "tainted_flow",
                    item.get("lineno"),
                    f"Tainted input reaches dangerous sink {item.get('sink')}. Argument: {item.get('argument')}",
                    item,
                )
            )

        for item in file_result.get("eval_exec_calls", []):
            findings.append(
                _make_finding(
                    "ast_analysis",
                    file_path,
                    "eval_exec",
                    item.get("lineno"),
                    f"Direct use of {item.get('detail')} detected.",
                    item,
                )
            )

        for item in file_result.get("unsafe_writes", []):
            findings.append(
                _make_finding(
                    "ast_analysis",
                    file_path,
                    "unsafe_write",
                    item.get("lineno"),
                    f"Unsafe file write detected: {item.get('detail')}",
                    item,
                )
            )

    return findings


def parse_pycfg_analysis_result(result: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    for file_result in result.get("files", []):
        file_path = file_result.get("file", "")

        for item in file_result.get("flows", []):
            path = item.get("path") or []
            path_text = " -> ".join(path[:5])
            findings.append(
                _make_finding(
                    "pycfg_analysis",
                    file_path,
                    "tainted_flow",
                    item.get("lineno"),
                    f"CFG tainted flow reaches {item.get('sink')}. Path: {path_text}",
                    item,
                )
            )

        for item in file_result.get("eval_exec_calls", []):
            findings.append(
                _make_finding(
                    "pycfg_analysis",
                    file_path,
                    "eval_exec",
                    item.get("lineno"),
                    f"CFG analysis detected use of {item.get('detail')}.",
                    item,
                )
            )

        for item in file_result.get("unsafe_writes", []):
            findings.append(
                _make_finding(
                    "pycfg_analysis",
                    file_path,
                    "unsafe_write",
                    item.get("lineno"),
                    f"CFG analysis detected unsafe file write: {item.get('detail')}",
                    item,
                )
            )

    return findings