"""sentinel-audit --dsn ... [--rest-url ... --anon-key ... --repo ... --deep --fix]  (flags fall back to SENTINEL_* env)"""
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
    ap.add_argument("--deep", action="store_true", help="tool-using agent instead of one prompt: ~5x cost, same accuracy on our bench")
    ap.add_argument("--fix", action="store_true", help="after the report, pick findings and print fix SQL (never executed)")
    a = ap.parse_args()
    if not a.dsn:
        ap.error("--dsn or SENTINEL_DSN is required")
    from database_sentinel.mcp_server.target import Target

    from .graph import build_graph
    target = Target(a.dsn, a.rest_url, a.anon_key, a.repo)
    try:
        if not a.fix:
            print(build_graph(deep=a.deep).invoke({}, context=target)["report"])
            return
        from langgraph.checkpoint.memory import MemorySaver
        from langgraph.types import Command

        graph, cfg = build_graph(MemorySaver(), fixes=True, deep=a.deep), {"configurable": {"thread_id": "cli"}}
        out = graph.invoke({}, cfg, context=target)
        print(out["report"])
        pause = out["__interrupt__"][0].value["findings"]
        picked = [f["i"] for f in pause
                  if input(f"Fix [{f['severity']}] {f['pattern_id']} {f['object']}? [y/N] ").strip().lower() == "y"]
        fixes = graph.invoke(Command(resume=picked), cfg, context=target).get("fixes", [])
        print("\n-- Review before running. Sentinel never executes this.\n" + "\n\n".join(fixes) if fixes else "No fixes selected.")
    except Exception as e:  # clean one-line error for CLI users
        raise SystemExit(f"sentinel-audit: {type(e).__name__}: {e}\n"
                         "Check --dsn, and SENTINEL_BASE_URL / SENTINEL_API_KEY / SENTINEL_MODEL for the LLM.")
