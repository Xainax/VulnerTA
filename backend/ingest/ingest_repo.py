import argparse, json, subprocess, sys, os, shutil, stat, time
from pathlib import Path

def run_bytes(cmd, cwd=None, ok_codes={0,1}, env=None):
    """Run a command, return stdout as bytes. Treat exit codes in ok_codes as success."""
    env = (os.environ.copy() if env is None else env)
    # Encourage UTF-8 in children
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if p.returncode not in ok_codes:
        # Decode for logging only (never crash on decode)
        print(p.stdout.decode("utf-8", "replace"))
        print(p.stderr.decode("utf-8", "replace"), file=sys.stderr)
        raise SystemExit(f"Command failed ({p.returncode}): {' '.join(cmd)}")
    return p.stdout

def rmtree_win_safe(path: Path):
    """Delete a directory tree on Windows even if files are read-only or briefly locked."""
    def onerror(func, p, exc_info):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except PermissionError:
            time.sleep(0.5)
            func(p)
    shutil.rmtree(path, onerror=onerror)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--sha", required=True)  # branch or commit; commit recommended
    ap.add_argument("--out", default="artifacts")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    workdir = Path("repo_checkout").resolve()
    if workdir.exists():
        rmtree_win_safe(workdir)

    # 1) Clone & checkout exact SHA (deterministic)
    subprocess.run(["git", "clone", "--no-checkout", args.repo, str(workdir)], check=True)
    subprocess.run(["git", "fetch", "origin", args.sha], cwd=workdir, check=True)
    subprocess.run(["git", "checkout", args.sha], cwd=workdir, check=True)

    # 2) Run Bandit -> write directly to file (avoid decoding)
    bandit_json = (out / "bandit.json").resolve()
    bandit_json.parent.mkdir(parents=True, exist_ok=True)
    bandit_cmd = [sys.executable, "-m", "bandit", "-f", "json", "-r", ".", "-o", str(bandit_json)]
    p = subprocess.run(bandit_cmd, cwd=workdir)
    if p.returncode not in (0, 1):  # 1 == findings found
        raise SystemExit(f"Bandit failed: {p.returncode}")

    # 3) Run Semgrep -> write directly to file (avoid decoding)
    semgrep_json = (out / "semgrep.json").resolve()
    semgrep_json.parent.mkdir(parents=True, exist_ok=True)
    semgrep_cmd = ["semgrep", "scan", "--config", "p/ci", "--json", "--output", str(semgrep_json)]
    p = subprocess.run(semgrep_cmd, cwd=workdir)
    if p.returncode not in (0, 1):  # 1 == findings found
        raise SystemExit(f"Semgrep failed: {p.returncode}")

    # 4) Metadata
    meta = {
        "repo_url": args.repo,
        "commit_sha": args.sha,
        "bandit_file": str(bandit_json),
        "semgrep_file": str(semgrep_json),
        "generated_by": "day1_ingest",
    }
    (out / "ingest_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"✅ Wrote {bandit_json}, {semgrep_json}, and ingest_meta.json to {out}")

if __name__ == "__main__":
    main()
