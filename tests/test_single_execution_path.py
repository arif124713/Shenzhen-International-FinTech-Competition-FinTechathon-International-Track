"""U-EXEC-05: only apps/api/services/executor.py may import rail_sim; U-EXEC-06 placeholder for the reader (S2)."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {ROOT / "apps/api/services/executor.py"}


def imports_rail_sim(path: Path) -> bool:
    for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(n, ast.Import) and any(a.name.split(".")[0] == "rail_sim" for a in n.names):
            return True
        if isinstance(n, ast.ImportFrom) and n.module and n.module.split(".")[0] == "rail_sim":
            return True
    return False


def test_only_the_executor_imports_the_rail_simulator():
    offenders = []
    for p in ROOT.rglob("*.py"):
        rel = p.relative_to(ROOT).parts
        if ".venv" in rel or "tests" in rel or rel[:2] == ("services", "rail_sim") or p in ALLOWED:
            continue
        if imports_rail_sim(p):
            offenders.append(str(p.relative_to(ROOT)))
    assert not offenders, offenders
    assert imports_rail_sim(next(iter(ALLOWED)))  # the allowed path really is the one that uses it
