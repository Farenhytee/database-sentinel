import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    dsn: str  # read-only auditor role
    rest_url: str = ""  # e.g. http://127.0.0.1:54321
    anon_key: str = ""
    repo_path: str | None = None

    @classmethod
    def from_env(cls) -> "Target":
        return cls(
            dsn=os.environ["SENTINEL_DSN"],
            rest_url=os.environ.get("SENTINEL_REST_URL", ""),
            anon_key=os.environ.get("SENTINEL_ANON_KEY", ""),
            repo_path=os.environ.get("SENTINEL_REPO") or None,
        )
