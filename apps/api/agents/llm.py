"""One LLM interface for reader/compiler/planner (CLAUDE.md §2). Model ids come from env, never hard-coded.

- AnthropicClient / OpenAICompatClient: live providers (OpenAI-compatible base_url lets us use DeepSeek).
- ReplayClient: deterministic fixtures so `make test`/`make eval` run offline (data/fixtures/llm_replay/).

Every call returns a raw JSON string that the caller validates against a Pydantic model. On validation
failure the caller retries once and then fails closed; we never "best effort parse" (CLAUDE.md §5).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..settings import settings


class LLMError(Exception):
    pass


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str
    prompt_version: str


class LLMClient(Protocol):
    def complete(self, *, system: str, user: str, prompt_version: str, images: list[str] | None = None) -> LLMResponse:
        ...


class ReplayClient:
    """Looks up a canned response by (prompt_version, sha256(system+user)). Deterministic and offline.

    Falls back to a prompt-version-level default fixture (key `<prompt_version>__default`) when no exact
    match exists, so the offline demo can respond to arbitrary structured inputs without a live model.
    """

    def __init__(self, fixtures_dir: Path | None = None):
        self._dir = fixtures_dir or (settings.fixtures_dir / "llm_replay")
        self._cache: dict[str, dict[str, Any]] = {}
        self._defaults: dict[str, dict[str, Any]] = {}
        if self._dir.exists():
            for path in self._dir.glob("*.json"):
                data = json.loads(path.read_text(encoding="utf-8"))
                self._cache[data["key"]] = data
                if data["key"].endswith("__default"):
                    self._defaults[data["key"].split("__", 1)[0]] = data

    @staticmethod
    def key_for(system: str, user: str, prompt_version: str) -> str:
        h = hashlib.sha256(f"{system}\x1f{user}".encode()).hexdigest()
        return f"{prompt_version}__{h}"  # "__" is filesystem-safe on every platform (":" is not, on Windows)

    def complete(self, *, system: str, user: str, prompt_version: str, images: list[str] | None = None) -> LLMResponse:
        key = self.key_for(system, user, prompt_version)
        hit = self._cache.get(key) or self._defaults.get(prompt_version)
        if hit is None:
            raise LLMError(f"no replay fixture for {key} (add data/fixtures/llm_replay/{key}.json)")
        return LLMResponse(text=json.dumps(hit["output"]), model=hit.get("model", "replay"), prompt_version=prompt_version)


class OpenAICompatClient:
    """Live client for any OpenAI-compatible /chat/completions endpoint (DeepSeek, OpenAI, ...)."""

    def __init__(self, *, base_url: str, api_key: str, model: str, temperature: int = 0, timeout: float = 60.0):
        if not api_key:
            raise LLMError("LLM_API_KEY is not set")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._timeout = timeout

    def complete(self, *, system: str, user: str, prompt_version: str, images: list[str] | None = None) -> LLMResponse:
        import urllib.request

        content: list[dict[str, Any]] = [{"type": "text", "text": user}]
        for img in images or []:
            content.append({"type": "image_url", "image_url": {"url": img}})
        payload = {
            "model": self._model,
            "temperature": self._temperature,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": content}],
            "response_format": {"type": "json_object"},
        }
        req = urllib.request.Request(
            f"{self._base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self._api_key}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 (trusted provider host)
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - surface a typed error, never a raw trace to callers
            raise LLMError(f"provider call failed: {type(exc).__name__}") from exc
        text = data["choices"][0]["message"]["content"]
        return LLMResponse(text=text, model=self._model, prompt_version=prompt_version)


class AnthropicClient:
    """Live Anthropic client. Kept thin; the reader is JSON-mode so we just return text."""

    def __init__(self, *, api_key: str, model: str, temperature: int = 0, timeout: float = 60.0):
        if not api_key:
            raise LLMError("LLM_API_KEY is not set")
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._timeout = timeout

    def complete(self, *, system: str, user: str, prompt_version: str, images: list[str] | None = None) -> LLMResponse:
        import urllib.request

        payload = {
            "model": self._model,
            "max_tokens": 2048,
            "temperature": self._temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "x-api-key": self._api_key, "anthropic-version": "2023-06-01"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise LLMError(f"provider call failed: {type(exc).__name__}") from exc
        text = "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")
        return LLMResponse(text=text, model=self._model, prompt_version=prompt_version)


class EchoPlannerClient:
    """Deterministic offline planner stand-in. Copies validated structured fields into a proposal.

    Exists so the offline demo/CI exercises the real engine, registry, executor and audit log with a
    planner that behaves predictably. It is NOT a model and makes no decisions; it will not invent payees.
    """

    def complete(self, *, system: str, user: str, prompt_version: str, images: list[str] | None = None) -> LLMResponse:
        payload = json.loads(user.split("\n", 1)[1])
        fields = payload.get("document_fields") or {}
        if not fields:
            return LLMResponse(text=json.dumps({"refusal": "no document fields"}), model="echo",
                               prompt_version=prompt_version)
        payee_known = fields.get("payee_name") == "Northfield University"
        proposal = {
            "action": "pay",
            "category": fields.get("category_guess", "other"),
            "payee_id": "reg_northfield_univ" if payee_known else None,
            "payee_ref": {"name": fields.get("payee_name"), "account_identifier": fields.get("account_identifier"),
                          "bank_identifier": fields.get("bank_identifier")},
            "amount_minor": fields.get("amount_minor"),
            "currency": fields.get("currency", "USD"),
            "source_account": payload.get("source_account", "acc_rafi_usd"),
            "source_debit_minor": (fields.get("amount_minor") or 0) + 2000,
            "rail_id": "rail_a_bank", "urgency": "normal", "doc_ref": "doc1",
        }
        return LLMResponse(text=json.dumps(proposal), model="echo", prompt_version=prompt_version)


def build_client(*, role: str) -> LLMClient:
    """Factory used by routes/services. `role` selects the env model id for reader/planner/compiler."""
    provider = settings.llm_provider
    model = {
        "reader": settings.llm_model_reader,
        "planner": settings.llm_model_planner,
        "compiler": settings.llm_model_compiler,
    }.get(role, settings.llm_model_reader)
    if provider == "replay":
        if role == "planner":
            # In offline mode the planner is a deterministic stand-in that echoes validated structured
            # fields into an ActionProposal. It is an untrusted, injected component (CLAUDE.md invariant 6);
            # the engine, registry and executor that actually decide remain the genuine implementations.
            return EchoPlannerClient()
        return ReplayClient()
    if provider == "openai_compat":
        return OpenAICompatClient(base_url=settings.llm_base_url, api_key=settings.llm_api_key, model=model,
                                  temperature=settings.llm_temperature)
    if provider == "anthropic":
        return AnthropicClient(api_key=settings.llm_api_key, model=model, temperature=settings.llm_temperature)
    raise LLMError(f"unknown LLM_PROVIDER {provider!r}")
