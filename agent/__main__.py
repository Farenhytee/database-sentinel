"""python -m agent --dsn ... [--rest-url ... --anon-key ... --repo ...]"""
import argparse

from dotenv import load_dotenv

from mcp_server.target import Target

from .graph import build_graph

ap = argparse.ArgumentParser()
ap.add_argument("--dsn", required=True, help="read-only auditor role DSN")
ap.add_argument("--rest-url", default="")
ap.add_argument("--anon-key", default="")
ap.add_argument("--repo")
a = ap.parse_args()
load_dotenv()
out = build_graph().invoke({"target": Target(a.dsn, a.rest_url, a.anon_key, a.repo)})
print(out["report"])
