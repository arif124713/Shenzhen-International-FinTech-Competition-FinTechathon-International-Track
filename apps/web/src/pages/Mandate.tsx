import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import { MandateCard } from "../components/MandateCard";

/** Plain-language rendering of one stored rule for the active-mandate card. */
function ruleToText(rule: any): string {
  if (rule.type === "category_allow") return `allow ${rule.categories.join(" and ")}`;
  if (rule.type === "cap") return `up to ${(rule.amount_minor / 100).toFixed(0)} ${rule.currency} per ${scopeWord(rule.scope)}`;
  if (rule.type === "escalate_above") return `over ${(rule.amount_minor / 100).toFixed(0)} ${rule.currency} needs approval`;
  if (rule.type === "require_registry_match") return `only verified payees for ${rule.categories?.join(", ") ?? "these categories"}`;
  if (rule.type === "new_payee") return `new payees need approval`;
  if (rule.type === "cooling_off") return `new payees wait ${rule.hours} hours`;
  if (rule.type === "min_confidence") return `confidence checks on`;
  if (rule.type === "block_anomalies") return `hidden or instruction-like text is blocked`;
  return rule.type;
}

function scopeWord(scope: string): string {
  return scope === "per_tx" ? "payment" : scope.replace("rolling_", "rolling ");
}

/**
 * Pre-fill for the editor: only phrases the compiler understands. Rules the compiler always applies by
 * default (min_confidence, block_anomalies) are omitted so re-compiling the text round-trips cleanly.
 */
function ruleToEditableText(rule: any): string | null {
  if (rule.type === "category_allow") return `allow ${rule.categories.join(" and ")}`;
  if (rule.type === "cap") return `up to ${(rule.amount_minor / 100).toFixed(0)} ${rule.currency} per ${scopeWord(rule.scope)}`;
  if (rule.type === "escalate_above") return `over ${(rule.amount_minor / 100).toFixed(0)} ${rule.currency} needs approval`;
  if (rule.type === "require_registry_match") return `only verified payees for ${rule.categories?.join(", ") ?? "these categories"}`;
  if (rule.type === "new_payee") return `new payees need approval`;
  if (rule.type === "cooling_off") return `new payees wait ${rule.hours} hours`;
  return null; // internal-only rules (min_confidence, block_anomalies, rail_allow) are not user phrases
}

export function Mandate() {
  const { t, i18n } = useTranslation();
  const [text, setText] = useState("");
  const [candidate, setCandidate] = useState<any>(null);
  const [back, setBack] = useState("");
  const [clarification, setClarification] = useState("");
  const [tests, setTests] = useState<any[]>([]);
  const [signed, setSigned] = useState<any>(null);
  const [active, setActive] = useState<any>(null);
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");

  const loadActive = () => api.activeMandate().then(setActive).catch(() => setActive({ active: false }));
  useEffect(() => {
    loadActive();
  }, []);

  const compile = async () => {
    setBusy(true);
    setNotice("");
    const r = await api.compile(text, i18n.language);
    setCandidate(r.candidate);
    setBack(r.back_translation);
    setClarification(r.clarification);
    setTests(r.test_cases);
    setSigned(null);
    setBusy(false);
  };

  const confirm = async () => {
    if (!candidate) return;
    setBusy(true);
    const s = await api.confirm(candidate, back);
    setSigned(s);
    setEditing(false);
    setCandidate(null);
    setBack("");
    setTests([]);
    setText("");
    await loadActive();
    setBusy(false);
  };

  const startEdit = () => {
    // pre-fill only compiler-friendly phrases so re-compiling round-trips (internal-only rules are omitted)
    const rules = (active?.rules ?? [])
      .map(ruleToEditableText)
      .filter((s: string | null): s is string => Boolean(s))
      .join(", ");
    setText(rules);
    setEditing(true);
    setSigned(null);
    setNotice("");
  };

  const remove = async () => {
    if (!window.confirm(t("mandate.confirmDelete"))) return;
    setBusy(true);
    setNotice("");
    await api.deleteMandate();
    setCandidate(null);
    setBack("");
    setTests([]);
    setEditing(false);
    setText("");
    await loadActive();
    setNotice(t("mandate.deleted"));
    setBusy(false);
  };

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="mb-4 text-2xl font-bold">{t("nav.mandate")}</h1>

      {active?.active && (
        <MandateCard title={t("mandate.active")} version={active.version} signed>
          <ul className="list-disc pl-4">
            {active.rules.map((r: any) => (
              <li key={r.id}>{ruleToText(r)}</li>
            ))}
          </ul>
          <div className="mt-3 flex gap-2">
            <button className="h-10 rounded-control border border-seal px-4 text-seal" onClick={startEdit}>
              {t("mandate.edit")}
            </button>
            <button
              className="h-10 rounded-control border border-deny px-4 text-deny disabled:opacity-50"
              onClick={remove}
              disabled={busy}
            >
              {busy ? t("mandate.deleting") : t("mandate.delete")}
            </button>
          </div>
        </MandateCard>
      )}

      {notice && (
        <p role="status" className="mt-3 rounded-panel bg-hold-tint p-3 text-hold">
          {notice}
        </p>
      )}

      {!active?.active || editing ? (
        <>
          {editing && <p className="mt-4 text-sm text-ink-muted">{t("mandate.editing")}</p>}
          <label htmlFor="rules" className="mb-1 mt-3 block text-sm font-medium">
            {t("mandate.write")}
          </label>
          <textarea
            id="rules"
            lang={i18n.language}
            className="h-32 w-full rounded-control border border-line bg-surface p-3"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <p className="mt-1 text-sm text-ink-muted">{t("mandate.hint")}</p>
          <div className="mt-3 flex gap-2">
            <button
              className="h-11 rounded-control bg-seal px-5 text-white disabled:opacity-50"
              onClick={compile}
              disabled={busy || !text.trim()}
            >
              {t("mandate.compile")}
            </button>
            {candidate && !signed && (
              <button
                className="h-11 rounded-control border border-seal px-5 text-seal disabled:opacity-50"
                onClick={confirm}
                disabled={busy}
              >
                {t("mandate.confirm")}
              </button>
            )}
            {editing && (
              <button
                className="h-11 rounded-control px-5 text-ink-muted"
                onClick={() => {
                  setEditing(false);
                  setCandidate(null);
                  setBack("");
                  setTests([]);
                  setText("");
                }}
              >
                {t("mandate.cancelEdit")}
              </button>
            )}
          </div>

          {clarification && (
            <p role="alert" className="mt-3 rounded-panel bg-hold-tint p-3 text-hold">
              {clarification}
            </p>
          )}

          {back && (
            <section className="mt-4 rounded-panel border border-line bg-surface p-4">
              <h2 className="mb-1 text-base font-medium">{t("mandate.backTranslation")}</h2>
              <p>{back}</p>
              {tests.length > 0 && (
                <>
                  <h3 className="mt-3 text-sm font-medium">{t("mandate.tests")}</h3>
                  <ul className="list-disc pl-4 text-sm">
                    {tests.map((c, i) => (
                      <li key={i}>
                        {c.expect}: {c.category} — {c.note}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </section>
          )}

          {signed && (
            <p role="status" className="mt-3 rounded-panel bg-seal-tint p-3 text-seal">
              Mandate signed · v{signed.version}
            </p>
          )}
        </>
      ) : null}
    </div>
  );
}
