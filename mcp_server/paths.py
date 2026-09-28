from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
# Repo checkout has backends/ at root; an installed wheel ships it under sentinel_catalog/.
CATALOG = _ROOT if (_ROOT / "backends").is_dir() else _ROOT / "sentinel_catalog"
SUPABASE = CATALOG / "backends" / "supabase"
