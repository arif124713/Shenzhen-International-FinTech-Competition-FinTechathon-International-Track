import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useParams } from "react-router-dom";
import { api, money, type DecisionPayload } from "../api/client";
import { VerdictChip, type Verdict } from "../components/VerdictChip";

interface Summary {
  payee_name: string;
  amount_minor: number;
  currency: string;
  rail_id: string;
  reason: string;
  expires_hours: number;
}

/** Guardian approval page (mobile-first). Large type, equal-weight stacked actions (design.md §6.10).
 *  The payment summary is fetched from the token-bound endpoint, so the guardian does not paste JSON. */
export function Guardian() {
  const { t } = useTranslation();
  const { token = "" } = useParams();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [result, setResult] = useState<DecisionPayload | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .approvalSummary(token)
      .then((r) => setSummary(r.summary))
      .catch(() => setLoadError(true));
  }, [token]);

  const decide = async (approve: boolean) => {
    setBusy(true);
    setError("");
    try {
      // The server recomputes the action_hash from the stored proposal, so authority is unchanged.
      setResult(await api.approve(token, approve, null));
    } catch {
      setError(t("approve.notFound"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="mx-auto max-w-[480px] p-4 text-lg">
      <h1 className="mb-4 text-xl font-bold">{t("approve.title")}</h1>

      {loadError && (
        <p role="alert" className="rounded-panel bg-deny-tint p-3 text-deny">
          {t("approve.notFound")}
        </p>
      )}

      {!summary && !loadError && <p className="text-ink-muted">{t("approve.loading")}</p>}

      {summary && (
        <section className="rounded-panel border border-line bg-surface p-4">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-base">
            <dt className="text-ink-muted">{t("approve.payee")}</dt>
            <dd className="font-medium">{summary.payee_name}</dd>
            <dt className="text-ink-muted">{t("approve.amount")}</dt>
            <dd className="tnum font-bold">{money(summary.amount_minor, summary.currency)}</dd>
            <dt className="text-ink-muted">{t("approve.rail")}</dt>
            <dd>{summary.rail_id}</dd>
            <dt className="text-ink-muted">{t("approve.reason")}</dt>
            <dd>{summary.reason}</dd>
          </dl>
          <p className="mt-3 text-sm text-ink-muted">{t("approve.locked")}</p>
        </section>
      )}

      <div className="mt-4 flex flex-col gap-3">
        <button
          className="h-12 rounded-control bg-seal text-white disabled:opacity-50"
          onClick={() => decide(true)}
          disabled={busy || !summary}
        >
          {t("approve.approve")}
        </button>
        <button
          className="h-12 rounded-control border border-deny text-deny disabled:opacity-50"
          onClick={() => decide(false)}
          disabled={busy || !summary}
        >
          {t("approve.reject")}
        </button>
      </div>

      {error && (
        <p role="alert" className="mt-3 text-deny">
          {error}
        </p>
      )}
      {result && (
        <section className="mt-4">
          <VerdictChip verdict={result.decision as Verdict} />
          {result.status === "executed" && (
            <p role="status" className="mt-2 rounded-panel bg-seal-tint p-3 text-seal">
              {t("approve.approved")}
            </p>
          )}
          {result.status === "refused" && <p className="mt-2 text-deny">Refused ({result.exec_code}).</p>}
          {result.decision !== "ALLOW" && (
            <p role="status" className="mt-2 rounded-panel bg-deny-tint p-3 text-deny">
              {t("approve.rejected")}
            </p>
          )}
          {result.receipt && (
            <p className="tnum mt-1 text-sm">
              {money(result.receipt.amount_minor, result.receipt.currency)}
            </p>
          )}
        </section>
      )}
    </main>
  );
}
