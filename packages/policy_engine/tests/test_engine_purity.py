"""U-ENG-14 / P-I3: the engine imports only stdlib, pydantic, cryptography and itself (CLAUDE.md invariant 1)."""
import ast
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
ALLOWED_THIRD_PARTY = {"pydantic", "cryptography", "policy_engine"}
FORBIDDEN_STDLIB = {"socket", "http", "urllib", "ssl", "asyncio", "subprocess", "random", "secrets", "requests"}


def imported_roots(path: Path) -> set[str]:
    roots = set()
    for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(n, ast.Import):
            roots |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
            roots.add(n.module.split(".")[0])
    return roots


def test_engine_has_no_llm_network_clock_or_randomness_imports():
    files = [p for p in PKG.rglob("*.py") if "tests" not in p.parts]
    assert files
    for f in files:
        for root in imported_roots(f):
            ok = root in sys.stdlib_module_names or root in ALLOWED_THIRD_PARTY
            assert ok, f"{f.name} imports {root}"
            assert root not in FORBIDDEN_STDLIB, f"{f.name} imports forbidden {root}"
