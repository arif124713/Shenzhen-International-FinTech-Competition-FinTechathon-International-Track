import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";

export function Login({ onLogin }: { onLogin: (role: string) => void }) {
  const { t } = useTranslation();
  const [error, setError] = useState("");
  const go = async (username: string) => {
    try {
      const u = await api.login(username);
      onLogin(u.role);
    } catch {
      setError("Could not sign in.");
    }
  };
  return (
    <main className="mx-auto mt-16 max-w-md">
      <h1 className="mb-4 text-2xl font-bold">{t("login.title")}</h1>
      <div className="flex flex-col gap-3">
        <button className="h-11 rounded-control bg-seal text-white" onClick={() => go("rafi")}>
          {t("login.rafi")}
        </button>
        <button className="h-11 rounded-control border border-seal text-seal" onClick={() => go("ammu")}>
          {t("login.ammu")}
        </button>
      </div>
      {error && (
        <p role="alert" className="mt-3 text-deny">
          {error}
        </p>
      )}
    </main>
  );
}
