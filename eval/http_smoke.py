"""End-to-end HTTP smoke against a running API (the seeded demo script in testing.md §12)."""
from __future__ import annotations

import httpx

B = "http://127.0.0.1:8000/api/v1"


def main() -> None:
    c = httpx.Client(base_url=B, timeout=30)
    c.post("/auth/login", json={"username": "rafi"})
    comp = c.post("/mandates/compile", json={"text": "pay tuition only to my university up to 5000, "
                                                    "new payees need ammu approval", "lang": "en"}).json()
    c.post("/mandates/confirm", json={"body": comp["candidate"], "back_translation": comp["back_translation"]})
    print("mandate:", c.get("/mandates/active").json()["active"])

    pdf = open(r"F:\download\mandate-s1\mandate\data\fixtures\invoices\inv_genuine_northfield.pdf", "rb").read()
    fields = c.post("/documents", files={"file": ("inv_genuine_northfield.pdf", pdf, "application/pdf")}).json()["reader"]
    print("reader:", fields["payee_name"], fields["amount_minor"], "anomalies:", fields["anomalies"])

    d = c.post("/proposals", json={"user_request": "pay this invoice", "document_fields": fields}).json()
    print("genuine:", d["decision"], d["status"], d["reason_codes"])

    bad = dict(fields, account_identifier="NF0012345679")
    d2 = c.post("/proposals", json={"user_request": "pay", "document_fields": bad}).json()
    print("substituted:", d2["decision"], d2["reason_codes"])

    big = dict(fields, amount_minor=180000)
    d3 = c.post("/proposals", json={"user_request": "pay", "document_fields": big}).json()
    print("large:", d3["decision"], d3["status"], d3["required_approvers"])
    ap = c.post("/approvals/decision", json={"token": d3["approval"]["token"], "approve": True,
                                             "proposal": d3["proposal"]}).json()
    print("approved:", ap["decision"], ap["status"])

    print("audit:", c.get("/audit/verify").json())
    print("rails:", c.post("/rails/quote", json={"source": "BDT", "dest": "USD", "amount_minor": 500000}).json()["chosen_rail_id"])


if __name__ == "__main__":  # pragma: no cover
    main()
