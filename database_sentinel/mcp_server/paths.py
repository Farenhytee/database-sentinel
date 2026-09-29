from pathlib import Path

_PKG = Path(__file__).resolve().parents[1]
# Repo checkout: catalog lives at the repo root. Installed wheel: shipped as database_sentinel/catalog/.
CATALOG = _PKG.parent if (_PKG.parent / "backends").is_dir() else _PKG / "catalog"
SUPABASE = CATALOG / "backends" / "supabase"
