import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { api, money, type DecisionPayload, type ReaderOutput } from "../api/client";
import { DecisionTrace } from "../components/DecisionTrace";
import { UntrustedQuote } from "../components/UntrustedQuote";
import { VerdictChip, type Verdict } from "../components/VerdictChip";

export function Pay() {
  const { t } = useTranslation();
  const [reader, setReader] = useState<ReaderOutput | null>(null);
  const [untrusted, setUntrusted] = useState("");
  const [decision, setDecision] = useState<DecisionPayload | null>(null);
  const [busy, setBusy] = useState(false);
  const [hasMandate, setHasMandate] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .activeMandate()
      .then((m) => setHasMandate(Boolean(m?.active)))
      .catch(() => setHasMandate(false));
  }, []);

  const onUpload = async (file: File) => {
    setBusy(true);
    setDecision(null);
    setError(null);
    try {
      const r = await api.uploadDocument(file);
      setReader(r.reader);
      setUntrusted(r.untrusted_text);
    } catch (e: unknown) {
      setReader(null);
      setUntrusted("");
      const code = (e as { code?: string })?.code;
      setError(code === "READER_UNAVAILABLE" ? t("pay.readerUnavailable") : t("pay.uploadError"));
    } finally {
      setBusy(false);
    }
  };

  const send = async () => {
    if (!reader) return;
    setBusy(true);
    setError(null);
    try {
      setDecision(await api.propose("pay this invoice", reader));
    } catch (e: unknown) {
      const detail =
        (e as { detail?: { code?: string } })?.detail?.code ?? (e as Error)?.message ?? "";
      setError(t("pay.sendError", { detail }));
    } finally {
      setBusy(false);
    }
  };

  const verdict: Verdict = decision ? (decision.decision as Verdict) : "ALLOW";

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="mb-4 text-2xl font-bold">{t("nav.pay")}</h1>

      {hasMandate === false && (
        <p role="alert" className="mb-4 rounded-panel bg-hold-tint p-3 text-hold">
          {t("pay.needMandate")}{" "}
          <Link className="underline" to="/mandate">
            {t("pay.goMandate")} →
          </Link>
        </p>
      )}

      <div className="rounded-panel border border-line bg-surface p-4">
        <label htmlFor="file" className="mb-1 block text-sm font-medium">
          {t("pay.upload")}
        </label>
        <p className="mb-2 text-sm text-ink-muted">{t("pay.drop")}</p>
        <input
          id="file"
          type="file"
          accept="application/pdf,image/png,image/jpeg"
          onChange={(e) => e.target.files && onUpload(e.target.files[0])}
          className="text-sm"
        />
      </div>

      {error && (
        <p role="alert" className="mt-4 rounded-panel bg-deny-tint p-3 text-deny">
          {error}
        </p>
      )}

      {reader && (
        <section className="mt-4 rounded-panel border border-line bg-surface p-4">
          <h2 className="mb-2 text-base font-medium">{t("pay.found")}</h2>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-ink-muted">Payee</dt>
            <dd>{reader.payee_name}</dd>
            <dt className="text-ink-muted">Account</dt>
            <dd className="font-mono">{reader.account_identifier}</dd>
            <dt className="text-ink-muted">Amount</dt>
            <dd className="tnum font-bold">{money(reader.amount_minor, reader.currency)}</dd>
            <dt className="text-ink-muted">Due</dt>
            <dd>{reader.due_date ?? "—"}</dd>
            <dt className="text-ink-muted">{t("pay.confidence")}</dt>
            <dd className="tnum">{(reader.extraction_confidence_bp / 100).toFixed(2)}</dd>
          </dl>
          {reader.anomalies.length > 0 && (
            <p className="mt-2 text-sm text-deny">Anomalies: {reader.anomalies.join(", ")}</p>
          )}
        </section>
      )}

      {untrusted && (
        <div className="mt-4">
          <UntrustedQuote text={untrusted} />
        </div>
      )}

      {reader && !decision && (
        <button
          className="mt-4 h-11 rounded-control bg-seal px-5 text-white disabled:opacity-50"
          disabled={busy || hasMandate === false}
          onClick={send}
        >
          {t("pay.send")}
        </button>
      )}

      {decision && (
        <section className="mt-6 flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <VerdictChip verdict={verdict} />
            <span className="font-mono text-xs text-ink-muted">{decision.action_hash.slice(0, 12)}</span>
          </div>
          <DecisionTrace trace={decision.trace} verdict={decision.decision} />
          <ul className="text-sm">
            {decision.reasons.map((r, i) => (
              <li key={i}>• {r}</li>
            ))}
          </ul>
          {decision.status === "executed" && (
            <p role="status" className="rounded-panel bg-seal-tint p-3 text-seal">
              Payment sent (simulated) · {decision.receipt?.receipt_id}
            </p>
          )}
          {decision.status === "needs_approval" && (
            <div role="status" className="rounded-panel bg-hold-tint p-3 text-hold">
              <p className="font-medium">{t("pay.needsApproval")}</p>
              <p className="mt-1 text-sm">{t("pay.sendLink")}</p>
              <a
                className="mt-2 inline-block h-11 rounded-control bg-hold px-5 py-3 text-white"
                href={`/approve/${decision.approval?.token}`}
                target="_blank"
                rel="noreferrer"
              >
                {t("pay.openGuardian")}
              </a>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
