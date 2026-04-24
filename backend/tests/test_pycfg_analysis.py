from backend.analysis.pycfg_analysis import analyze_code, analyze_files


def test_simple_flow():
    code = """
user = input()
os.system(user)
"""
    res = analyze_code(code, filename="test.py")
    assert res["counts"]["tainted_flows"] == 1
    assert res["counts"]["unsafe_writes"] == 0
    assert len(res.get("flows", [])) == 1
    assert res["risk"] >= 5
    assert "cfg" in res


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
    f1.write_text("user = input()\nos.system(user)\n")
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
