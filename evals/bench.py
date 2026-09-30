"""Local-Supabase bench plumbing: load cases, reset DB, apply a case, build its Target."""
import hashlib
import json
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import psycopg
import yaml

from database_sentinel.mcp_server.setup import role_sql
from database_sentinel.mcp_server.target import Target

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "bench"
AUDITOR = ("sentinel_auditor", "sentinel_local_only")


def local_env(tries: int = 5) -> dict:
    for i in range(tries):  # services can be restarting right after a reset
        out = subprocess.run(["supabase", "status", "-o", "json"], cwd=ROOT, capture_output=True, text=True)
        if out.returncode == 0:
            return json.loads(out.stdout[out.stdout.index("{"):])
        time.sleep(5)
    raise SystemExit(f"local Supabase not running: {out.stderr.strip()[:200]}  (run: supabase start)")


def split(name: str) -> list[str]:
    return yaml.safe_load((BENCH / "splits.yaml").read_text())[name] or []


def case_dir(cid: str) -> Path:
    return next((BENCH / "cases").glob(f"{cid}-*"))


def labels(cid: str) -> list[dict]:
    return yaml.safe_load((case_dir(cid) / "labels.yaml").read_text())["findings"] or []


def prepare(cid: str, env: dict) -> None:
    # The only destructive op in the repo: wipes the throwaway LOCAL bench DB. Never remote.
    if urlparse(env["DB_URL"]).hostname not in ("127.0.0.1", "localhost"):
        raise RuntimeError(f"refusing to reset non-local DB {urlparse(env['DB_URL']).hostname}")
    subprocess.run(["supabase", "db", "reset"], cwd=ROOT, capture_output=True, check=True)
    with psycopg.connect(env["DB_URL"], autocommit=True) as conn:
        conn.execute(role_sql().replace("CHANGE_ME_TO_A_STRONG_PASSWORD", AUDITOR[1]))
        conn.execute((BENCH / "seed_users.sql").read_text())
        conn.execute((case_dir(cid) / "schema.sql").read_text())
        conn.execute("notify pgrst, 'reload schema'")


def target(cid: str, env: dict) -> Target:
    user, pw = AUDITOR
    dsn = env["DB_URL"].replace("postgres:postgres@", f"{user}:{pw}@", 1)
    fe = case_dir(cid) / "frontend"
    return Target(dsn=dsn, rest_url=env["API_URL"], anon_key=env["ANON_KEY"],
                  repo_path=str(fe) if fe.is_dir() else None)


LOCK = BENCH / "test.lock"


def case_hash(cid: str) -> str:
    d = case_dir(cid)
    h = hashlib.sha256()
    for f in sorted(p for p in d.rglob("*") if p.is_file()):
        h.update(str(f.relative_to(d)).encode() + b"\0" + f.read_bytes() + b"\0")
    return h.hexdigest()


def write_lock() -> None:
    """Freeze the test split. Run once, when the test cases are accepted."""
    LOCK.write_text(json.dumps({c: case_hash(c) for c in split("test")}, indent=2) + "\n")


def check_lock() -> None:
    lock = json.loads(LOCK.read_text()) if LOCK.exists() else {}
    if not lock or set(lock) != set(split("test")) or any(case_hash(c) != h for c, h in lock.items()):
        raise SystemExit("test split is not frozen or was modified (bench/test.lock). Test cases are never edited.")
