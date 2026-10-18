/** Typed API client. Every value shown comes from the backend; numbers are never typed by hand. */

export interface ReaderOutput {
  doc_type: string;
  payee_name: string;
  account_identifier: string;
  bank_identifier: string;
  amount_minor: number;
  currency: string;
  due_date: string | null;
  reference: string;
  category_guess: string;
  extraction_confidence_bp: number;
  anomalies: string[];
}

export interface TraceStep {
  step: string;
  result: "pass" | "hold" | "escalate" | "deny" | "skipped";
  detail: string;
}

export interface DecisionPayload {
  proposal: Record<string, unknown>;
  decision: "ALLOW" | "HOLD" | "ESCALATE" | "DENY";
  tier: string;
  reason_codes: string[];
  reasons: string[];
  failed_rule_ids: string[];
  required_approvers: string[];
  hold_until: string | null;
  deadline_at_risk: boolean;
  trace: TraceStep[];
  action_hash: string;
  status?: string;
  receipt?: { receipt_id: string; amount_minor: number; currency: string; simulated: boolean };
  approval?: { token: string; approver_id: string; expires_at: string };
  balances?: Record<string, number>;
  exec_code?: string;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    ...init,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw Object.assign(new Error("request failed"), { status: res.status, detail });
  }
  return res.json() as Promise<T>;
}

export const api = {
  login: (username: string) => req<{ user_id: string; name: string; role: string; lang: string }>("/auth/login", { method: "POST", body: JSON.stringify({ username }) }),
  compile: (text: string, lang: string) => req<{ status: string; candidate: any; back_translation: string; clarification: string; test_cases: any[] }>("/mandates/compile", { method: "POST", body: JSON.stringify({ text, lang }) }),
  confirm: (body: any, back_translation: string) => req<any>("/mandates/confirm", { method: "POST", body: JSON.stringify({ body, back_translation }) }),
  activeMandate: () => req<any>("/mandates/active"),
  deleteMandate: () => req<{ status: string; active: boolean; deleted_version?: number }>("/mandates/active", { method: "DELETE" }),
  uploadDocument: async (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch("/api/v1/documents", { method: "POST", body: fd, credentials: "include" });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      const detail = body?.detail;
      throw Object.assign(new Error("upload failed"), { status: res.status, code: detail?.code });
    }
    return res.json() as Promise<{ document_id: string; mime: string; reader: ReaderOutput; anomalies: string[]; untrusted_text: string }>;
  },
  propose: (user_request: string, document_fields: ReaderOutput | null, source_account = "acc_rafi_usd") =>
    req<DecisionPayload>("/proposals", { method: "POST", body: JSON.stringify({ user_request, document_fields, source_account }) }),
  approve: (token: string, approve: boolean, proposal: any) =>
    req<DecisionPayload>("/approvals/decision", { method: "POST", body: JSON.stringify({ token, approve, proposal, approver_id: "u_ammu" }) }),
  approvalSummary: (token: string) =>
    req<{ summary: { payee_name: string; amount_minor: number; currency: string; rail_id: string; reason: string; expires_hours: number } }>(`/approvals/${encodeURIComponent(token)}`),
  rails: (source: string, dest: string, amount_minor: number, urgency = "normal") =>
    req<any>("/rails/quote", { method: "POST", body: JSON.stringify({ source, dest, amount_minor, urgency }) }),
  balances: () => req<{ balances: { account_id: string; currency: string; balance_minor: number }[] }>("/balances"),
  audit: () => req<{ entries: any[] }>("/audit"),
  verifyAudit: () => req<{ valid: boolean; first_bad_seq: number | null; entries: number }>("/audit/verify"),
  report: () => req<{ available: boolean; report?: any; message?: string }>("/eval/report"),
  registry: () => req<{ registry_version: string; entries: any[]; trust_note: string }>("/registry"),
  addRegistryEntry: (payload: { legal_name: string; account_identifier: string; bank_identifier: string; source_url?: string }) =>
    req<{ status: string; entry: any }>("/registry", { method: "POST", body: JSON.stringify(payload) }),
  revokeRegistryEntry: (entityId: string) =>
    req<{ status: string; entry: any }>(`/registry/${encodeURIComponent(entityId)}/revoke`, { method: "POST" }),
};

export function money(minor: number, currency: string): string {
  const sign = minor < 0 ? "-" : "";
  const abs = Math.abs(minor);
  const whole = Math.floor(abs / 100);
  const frac = String(abs % 100).padStart(2, "0");
  return `${sign}${whole.toLocaleString("en-US")}.${frac} ${currency}`;
}
