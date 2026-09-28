import json

import psycopg
from psycopg.rows import dict_row

ROW_CAP = 200
_OPTS = "-c default_transaction_read_only=on -c statement_timeout=5000"


def query(dsn: str, sql: str, params: tuple | None = None) -> list[dict]:
    with psycopg.connect(dsn, options=_OPTS, row_factory=dict_row, connect_timeout=10) as conn:
        conn.read_only = True  # every transaction READ ONLY, on top of the role default
        rows = conn.execute(sql, params).fetchmany(ROW_CAP)
    return json.loads(json.dumps(rows, default=str))  # JSON-safe for LLM + MCP
