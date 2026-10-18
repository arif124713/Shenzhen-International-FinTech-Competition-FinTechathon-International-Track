import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";

/** Verified payees (the signed registry). Judges and users can see provenance and add a team-enrolled payee.
 *  A signature proves the record was not altered — it does NOT prove the institution is genuine (stated here). */
export function RegistryPage() {
  const { t } = useTranslation();
  const [state, setState] = useState<{ registry_version: string; entries: any[]; trust_note: string } | null>(null);
  const [form, setForm] = useState({ legal_name: "", account_identifier: "", bank_identifier: "", source_url: "" });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const load = () => api.registry().then(setState).catch(() => setState(null));
  useEffect(() => {
    load();
  }, []);

  const add = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await api.addRegistryEntry(form);
      setMessage({ kind: "ok", text: t("registry.added") });
      setForm({ legal_name: "", account_identifier: "", bank_identifier: "", source_url: "" });
      await load();
    } catch (e: unknown) {
      const code = (e as { detail?: { code?: string } })?.detail?.code;
      setMessage({ kind: "err", text: code === "REGISTRY_ENTITY_EXISTS" ? t("registry.exists") : t("registry.invalid") });
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (entityId: string) => {
    if (!window.confirm(t("registry.revokeConfirm"))) return;
    try {
      await api.revokeRegistryEntry(entityId);
      await load();
    } catch {
      setMessage({ kind: "err", text: t("registry.invalid") });
    }
  };

  const canSave = form.legal_name.trim() && form.account_identifier.trim() && form.bank_identifier.trim();

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="mb-2 text-2xl font-bold">{t("registry.title")}</h1>
      <p className="mb-2 text-sm text-ink-muted">{t("registry.intro")}</p>
      <p className="mb-4 rounded-panel bg-untrusted-tint p-3 text-sm text-untrusted">{t("registry.trustNote")}</p>

      <section className="rounded-panel border border-line bg-surface p-4">
        <h2 className="mb-3 text-base font-medium">{t("registry.add")}</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="text-sm">
            {t("registry.name")}
            <input className="mt-1 w-full rounded-control border border-line bg-surface p-2"
                   value={form.legal_name} onChange={(e) => setForm({ ...form, legal_name: e.target.value })} />
          </label>
          <label className="text-sm">
            {t("registry.account")}
            <input className="mt-1 w-full rounded-control border border-line bg-surface p-2 font-mono"
                   value={form.account_identifier}
                   onChange={(e) => setForm({ ...form, account_identifier: e.target.value })} />
          </label>
          <label className="text-sm">
            {t("registry.bank")}
            <input className="mt-1 w-full rounded-control border border-line bg-surface p-2 font-mono"
                   value={form.bank_identifier}
                   onChange={(e) => setForm({ ...form, bank_identifier: e.target.value })} />
          </label>
          <label className="text-sm">
            {t("registry.source")}
            <input className="mt-1 w-full rounded-control border border-line bg-surface p-2"
                   value={form.source_url} onChange={(e) => setForm({ ...form, source_url: e.target.value })} />
          </label>
        </div>
        <button className="mt-3 h-11 rounded-control bg-seal px-5 text-white disabled:opacity-50"
                onClick={add} disabled={busy || !canSave}>
          {busy ? t("registry.saving") : t("registry.save")}
        </button>
        {message && (
          <p role="status" className={`mt-3 rounded-panel p-3 ${message.kind === "ok" ? "bg-seal-tint text-seal" : "bg-deny-tint text-deny"}`}>
            {message.text}
          </p>
        )}
      </section>

      <section className="mt-6">
        <h2 className="mb-2 text-base font-medium">
          {t("registry.title")} · v{state?.registry_version ?? "—"}
        </h2>
        {!state || state.entries.length === 0 ? (
          <p className="text-ink-muted">{t("registry.empty")}</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {state.entries.map((e) => {
              const revoked = Boolean(e.revoked_at);
              return (
                <li key={e.entity_id} className="rounded-panel border border-line bg-surface p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="font-medium">{e.legal_name}</p>
                      <p className="font-mono text-xs text-ink-muted">
                        {e.account_identifier} · {e.bank_identifier}
                      </p>
                      <p className="mt-1 text-xs text-ink-muted">
                        {t("registry.provenance")}: {e.provenance?.method ?? "—"}
                      </p>
                    </div>
                    {revoked ? (
                      <span className="rounded-full border border-deny px-3 py-1 text-xs text-deny">{t("registry.revoked")}</span>
                    ) : (
                      <button className="h-9 rounded-control border border-deny px-3 text-sm text-deny"
                              onClick={() => revoke(e.entity_id)}>
                        {t("registry.revoke")}
                      </button>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </div>
  );
}
