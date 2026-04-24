from backend.analysis.ast_analysis import analyze_code, analyze_files


def test_simple_flow():
    code = """
user = input()
eval(user)
"""
    res = analyze_code(code, filename="test.py")
    assert res["counts"]["tainted_flows"] == 1
    assert res["counts"]["eval_exec"] == 1
    assert len(res.get("flows", [])) == 1
    # the flow should include a human-readable trace back to the source
    flow = res["flows"][0]
    assert "trace" in flow and "input" in flow["trace"]
    assert res["risk"] >= 5


def test_eval_only():
    code = """
eval('1 + 1')
"""
    res = analyze_code(code)
    assert res["counts"]["eval_exec"] == 1
    assert res["counts"]["tainted_flows"] == 0
    assert len(res.get("eval_exec_calls", [])) == 1


def test_unsafe_write():
    code = """
f = open('a.txt', 'w')
f.write('hello')
"""
    res = analyze_code(code)
    assert res["counts"]["unsafe_writes"] == 1


def test_multiple_files(tmp_path):
    f1 = tmp_path / "a.py"
    f1.write_text("user = input()\neval(user)\n")
    f2 = tmp_path / "b.py"
    f2.write_text("open('x','w')\n")
    files = [
        {"path": str(f1), "content": f1.read_text()},
        {"path": str(f2), "content": f2.read_text()},
    ]
    res = analyze_files(files)
    assert res["counts"]["tainted_flows"] == 1
    assert res["counts"]["unsafe_writes"] == 1
    assert res["files_analyzed"] == 2


def test_source_catalog_and_trace():
    code = """
import sys
value = sys.argv[0]
exec(value)
"""
    res = analyze_code(code)
    assert res["counts"]["tainted_flows"] == 1
    assert res["flows"]
    trace = res["flows"][0].get("trace", "")
    assert "sys.argv" in trace


def test_format_flow():
    from backend.analysis.ast_analysis import format_flow, _risk_label_for_sink

    flow = {
        "sink": "eval_exec",
        "lineno": 20,
        "argument": "user_data",
        "trace": "input(input())@12",
    }
    text = format_flow(flow, risk_label=_risk_label_for_sink(flow["sink"]))
    assert "Source: input(input()) at line 12" in text
    assert "Assigned to: user_data" in text
    assert "Passed to: eval_exec() at line 20" in text
    assert "Remote Code Execution" in text


def test_print_flow():
    """Demonstrate the taint flow output so you can see it when running with -s."""
    from backend.analysis.ast_analysis import format_flow, _risk_label_for_sink

    code = """
user = input()
eval(user)
"""
    res = analyze_code(code, filename="demo.py")
    for flow in res.get("flows", []):
        print(format_flow(flow, risk_label=_risk_label_for_sink(flow["sink"])))
    # ensure there was at least one flow so the print happens
    assert res["counts"]["tainted_flows"] >= 1


def test_pycfg_generation():
    from backend.analysis.pycfg_analysis import get_cfg_from_code

    code = "user = input()\neval(user)\n"
    cfg = get_cfg_from_code(code)

    assert isinstance(cfg, dict)
    assert "nodes" in cfg and "edges" in cfg
    assert len(cfg["nodes"]) >= 3
    assert any(node["lineno"] == 1 for node in cfg["nodes"])
    assert any(node["lineno"] == 2 for node in cfg["nodes"])
    assert all("id" in node and "ast" in node for node in cfg["nodes"])


def test_analyze_code_includes_cfg():
    res = analyze_code("user = input()\neval(user)\n")
    assert "cfg" in res
    assert isinstance(res["cfg"], dict)
    assert res["cfg"]["nodes"]
    assert res["cfg"]["edges"]


def test_cfg_flow_contains_source_and_sink_nodes():
    res = analyze_code("user = input()\neval(user)\n")
    cfg = res["cfg"]

    node_map = {node["id"]: node for node in cfg["nodes"]}
    assert any(node["lineno"] == 1 and "input" in node["ast"] for node in cfg["nodes"])
    assert any(node["lineno"] == 2 and "eval" in node["ast"] for node in cfg["nodes"])
    assert any(edge["from"] in node_map and edge["to"] in node_map for edge in cfg["edges"])
    assert cfg["dominators"]
    assert cfg["postdominators"]


def test_flow_vulnerabilities_are_reported():
    from backend.analysis.ast_analysis import format_flow, _risk_label_for_sink

    res = analyze_code("user = input()\neval(user)\n")
    assert res["flows"]
    flow = res["flows"][0]
    assert flow["vulnerabilities"] == ["Input Handling", "Remote Code Execution"]
    assert "Vulnerabilities" in format_flow(flow, risk_label=_risk_label_for_sink(flow["sink"]))

