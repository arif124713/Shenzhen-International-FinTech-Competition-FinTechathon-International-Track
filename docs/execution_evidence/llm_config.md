# LLM configuration evidence

- Confirmed model IDs: reader/planner/compiler = `deepseek-v4.1-flash` (from env; verify in the official DeepSeek docs before submission).
- Base URL: `https://api.deepseek.com/v1` (env `LLM_BASE_URL`).
- Provider mode for this evidence run: `replay` (replay = offline fixtures).
- Temperature: 0. Reasoning/thinking mode: off for extraction and compilation.
- Reader mode: determined by the start-up capability probe (`READER_MODE`); text mode is used if the configured model rejects images. Never crashes on rejection.
- Evidence generated: 2026-10-18T21:20:55.563320+00:00.

> All calls are simulated/synthetic. No real passport, bank or personal data leaves the machine.
