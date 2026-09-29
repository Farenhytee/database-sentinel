"""sentinel-audit --dsn ... [--rest-url ... --anon-key ... --repo ...]  (flags fall back to SENTINEL_* env)"""
import argparse
import os


def main() -> None:
    try:
        from dotenv import load_dotenv
        import langgraph  # noqa: F401
    except ImportError:
        raise SystemExit('sentinel-audit needs the agent extra: pip install "database-sentinel[agent] @ git+https://github.com/Farenhytee/database-sentinel"')

    load_dotenv()
    ap = argparse.ArgumentParser(prog="sentinel-audit")
    ap.add_argument("--dsn", default=os.environ.get("SENTINEL_DSN"), help="read-only auditor role DSN")
    ap.add_argument("--rest-url", default=os.environ.get("SENTINEL_REST_URL", ""))
    ap.add_argument("--anon-key", default=os.environ.get("SENTINEL_ANON_KEY", ""))
    ap.add_argument("--repo", default=os.environ.get("SENTINEL_REPO"))
    a = ap.parse_args()
    if not a.dsn:
        ap.error("--dsn or SENTINEL_DSN is required")
    from database_sentinel.mcp_server.target import Target

    from .graph import build_graph
    try:
        out = build_graph().invoke({"target": Target(a.dsn, a.rest_url, a.anon_key, a.repo)})
    except Exception as e:  # clean one-line error for CLI users
        raise SystemExit(f"sentinel-audit: {type(e).__name__}: {e}\n"
                         "Check --dsn, and SENTINEL_BASE_URL / SENTINEL_API_KEY / SENTINEL_MODEL for the LLM.")
    print(out["report"])
