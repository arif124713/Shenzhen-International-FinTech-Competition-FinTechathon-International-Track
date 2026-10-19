# live_verification.md — hosted-demo end-to-end check

> A manual end-to-end pass against the **deployed** link (Vercel Python serverless), performed 2026-10-19.
> Screenshots in `screenshots/live-01…11-*.png`. Everything is SIMULATED.

- URL: https://mandate-nu-ten.vercel.app
- Backend: FastAPI on Vercel Python serverless, `LLM_PROVIDER=replay` (offline fixtures; no API key on the host).
- Statefulness caveat: serverless state (ledger/approvals/hold) does not persist across invocations; a demo
  mandate is seeded on cold start. This is a UI/flow demo. The **deterministic** run is `make dev` locally.

## Results (all passed on the live link)

| Step | Expected | Observed |
|---|---|---|
| Dashboard | mandate v1 signed, balances | ✔ `Signed ✓`, BDT/USD/GBP/EUR (live-01) |
| Pay · genuine invoice (`inv_genuine_northfield.pdf`) | Allowed | ✔ **Allowed** (live-02 extraction, live-03) |
| Pay · substituted account (`inv_substituted_account.pdf`) | Blocked (registry) | ✔ **Blocked** — "This account is not the one your university uses." (live-04) |
| Pay · hidden text (`inv_hidden_text.pdf`) | Blocked (anomaly) | ✔ **Blocked** (live-05) |
| Pay · large amount (`inv_large_amount.pdf`) | Needs approval | ✔ **Needs approval** + guardian link (live-06) |
| Guardian page @360px | summary + lock text | ✔ "locked to this exact payment and expires in 24 hours" (live-07) |
| Registry | trust sentence + entry | ✔ "A signature shows the record hasn't been changed. It doesn't prove the institution is genuine." (live-08) |
| Activity · Verify chain | Chain valid | ✔ **Chain valid** (live-09) |
| Red-team | live report numbers | ✔ B0 69.8% · B1 40.6% · B2 0.0% · 96 attacks (live-10) |
| Bangla toggle | Bangla banner | ✔ "সিমুলেটেড — আসল টাকা যায় না" (live-11) |

## API checks (curl / fetch)

- `GET /api/v1/health` → `200 {"status":"ok","banner":"Simulated - no real money moves"}`
- `GET /api/v1/mandates/active` → `active: true`, mandate v1 signed (seeded on cold start)
- `POST /api/v1/documents` (genuine PDF) → `200`, correct extraction + escaped untrusted text
- `POST /api/v1/proposals` → decision + trace + reason codes

This is a **flow** verification of the deployed build. The numbers reported elsewhere in the repo come from the
offline `make eval` run (`eval/reports/latest.json`), not from this hosted check.
