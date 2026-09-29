"""Local-Supabase bench plumbing: load cases, reset DB, apply a case, build its Target."""
import json
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import psycopg
import yaml

from database_sentinel.mcp_server.setup import role_sql
from database_sentinel.mcp_server.target import Target

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "bench"
AUDITOR = ("sentinel_auditor", "sentinel_local_only")


def local_env() -> dict:
    out = subprocess.run(["supabase", "status", "-o", "json"], cwd=ROOT, capture_output=True, text=True, check=True)
    return json.loads(out.stdout[out.stdout.index("{"):])


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
        conn.execute((case_dir(cid) / "schema.sql").read_text())
        conn.execute("notify pgrst, 'reload schema'")


def target(cid: str, env: dict) -> Target:
    user, pw = AUDITOR
    dsn = env["DB_URL"].replace("postgres:postgres@", f"{user}:{pw}@", 1)
    fe = case_dir(cid) / "frontend"
    return Target(dsn=dsn, rest_url=env["API_URL"], anon_key=env["ANON_KEY"],
                  repo_path=str(fe) if fe.is_dir() else None)
