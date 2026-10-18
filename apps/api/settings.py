"""Runtime settings, loaded from env with repo-relative defaults (implementation_plan §2.1)."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@lru_cache(maxsize=1)
def _load_dotenv() -> dict[str, str]:
    """Minimal .env reader (no dependency). Never overrides real environment variables."""
    values: dict[str, str] = {}
    path = REPO_ROOT / ".env"
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.split("#", 1)[0].strip()
    return values


def get(name: str, default: str = "") -> str:
    if name in os.environ:
        return os.environ[name]
    return _load_dotenv().get(name, default)


class Settings:
    """Simple attribute accessor over env vars. repo-relative paths only, no absolute paths committed."""

    @property
    def repo_root(self) -> Path:
        return REPO_ROOT

    @property
    def llm_provider(self) -> str:
        return get("LLM_PROVIDER", "replay")

    @property
    def llm_base_url(self) -> str:
        return get("LLM_BASE_URL", "https://api.deepseek.com/v1")

    @property
    def llm_api_key(self) -> str:
        return get("LLM_API_KEY", "")

    @property
    def llm_model_reader(self) -> str:
        return get("LLM_MODEL_READER", "deepseek-v4.1-flash")

    @property
    def llm_model_planner(self) -> str:
        return get("LLM_MODEL_PLANNER", "deepseek-v4.1-flash")

    @property
    def llm_model_compiler(self) -> str:
        return get("LLM_MODEL_COMPILER", "deepseek-v4.1-flash")

    @property
    def llm_temperature(self) -> int:
        return int(get("LLM_TEMPERATURE", "0"))

    @property
    def database_url(self) -> str:
        return get("DATABASE_URL", f"sqlite:///{(REPO_ROOT / 'mandate.db').as_posix()}")

    @property
    def eval_seed(self) -> int:
        return int(get("EVAL_SEED", "1337"))

    @property
    def cooling_off_hours_default(self) -> int:
        return int(get("COOLING_OFF_HOURS_DEFAULT", "24"))

    @property
    def sandbox_banner(self) -> str:
        return get("SANDBOX_BANNER", "Simulated - no real money moves")

    @property
    def demo_mode(self) -> bool:
        return get("DEMO_MODE", "1") == "1"

    @property
    def fixtures_dir(self) -> Path:
        return REPO_ROOT / "data" / "fixtures"

    @property
    def registry_dir(self) -> Path:
        return REPO_ROOT / "data" / "registry"

    @property
    def ratecards_path(self) -> Path:
        return REPO_ROOT / "data" / "ratecards" / "ratecards.json"

    @property
    def seed_dir(self) -> Path:
        return REPO_ROOT / "data" / "seed"

    @property
    def uploads_dir(self) -> Path:
        return REPO_ROOT / "data" / "uploads"

    @property
    def reports_dir(self) -> Path:
        return REPO_ROOT / "eval" / "reports"


settings = Settings()
