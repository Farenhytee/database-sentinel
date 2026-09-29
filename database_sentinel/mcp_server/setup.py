from .paths import SUPABASE


def role_sql() -> str:
    """SQL that creates the read-only sentinel_auditor role (user sets the password)."""
    return (SUPABASE / "auditor-role.sql").read_text()
