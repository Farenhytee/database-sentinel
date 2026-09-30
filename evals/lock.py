"""python -m evals.lock: freeze the test split (writes bench/test.lock). Run once."""
from .bench import LOCK, write_lock

if LOCK.exists():
    raise SystemExit("bench/test.lock already exists; the test split is frozen.")
write_lock()
print(f"wrote {LOCK}")
