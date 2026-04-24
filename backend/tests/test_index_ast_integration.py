from pathlib import Path

from backend.index.store_faiss import build_ast_findings
from backend.normalize.linker import link_findings
from backend.normalize.parse_static import ToolName


def test_build_ast_and_pycfg_findings(tmp_path: Path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    sample_code = """import subprocess
user_input = input('cmd> ')
subprocess.run(user_input, shell=True)
"""
    (repo_root / "app.py").write_text(sample_code, encoding="utf-8")

    findings = build_ast_findings(str(repo_root))

    assert any(f.meta.tool == ToolName.ast for f in findings), "Expected AST findings"
    assert any(f.meta.tool == ToolName.pycfg for f in findings), "Expected pycfg findings"

    ast_finding = next(f for f in findings if f.meta.tool == ToolName.ast)
    assert ast_finding.meta.rule_id == "os_command"
    assert "Input Handling" in ast_finding.message or "OS Command Injection" in ast_finding.message

    pycfg_finding = next(f for f in findings if f.meta.tool == ToolName.pycfg)
    assert "Control-flow graph analysis" in pycfg_finding.message

    nvd_path = tmp_path / "nvd.json"
    nvd_path.write_text("[]", encoding="utf-8")
    linked, _ = link_findings(findings, cve_cache_path=str(nvd_path))
    linked_ast = next(f for f in linked if f.meta.tool == ToolName.ast)
    assert "CWE-78" in linked_ast.cwe.cwe_ids
