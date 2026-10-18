import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";

export function Activity() {
  const { t } = useTranslation();
  const [entries, setEntries] = useState<any[]>([]);
  const [verify, setVerify] = useState<{ valid: boolean; first_bad_seq: number | null } | null>(null);
  useEffect(() => {
    api.audit().then((a) => setEntries(a.entries));
  }, []);

  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t("activity.title")}</h1>
        <button className="h-11 rounded-control border border-seal px-5 text-seal" onClick={() => api.verifyAudit().then(setVerify)}>
          {t("activity.verify")}
        </button>
      </div>
      {verify && (
        <p
          role="status"
          className={`mb-4 rounded-panel p-3 ${verify.valid ? "bg-seal-tint text-seal" : "bg-deny-tint text-deny"}`}
        >
          {verify.valid ? t("activity.chainValid") : t("activity.chainBroken", { seq: verify.first_bad_seq })}
        </p>
      )}
      <ul className="divide-y divide-line rounded-panel border border-line bg-surface">
        {entries.map((e) => (
          <li key={e.seq} className="p-3">
            <div className="flex items-center justify-between text-sm">
              <span className="font-mono">{e.seq} · {e.event_type}</span>
              <span className="text-ink-muted">{e.ts}</span>
            </div>
            <div className="font-mono text-xs text-ink-muted">
              {e.actor} · {e.hash.slice(0, 16)}…
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
