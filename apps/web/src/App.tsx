import { useTranslation } from "react-i18next";
import { NavLink, Outlet } from "react-router-dom";

const NAV = [
  { to: "/", key: "nav.home" },
  { to: "/pay", key: "nav.pay" },
  { to: "/mandate", key: "nav.mandate" },
  { to: "/registry", key: "nav.registry" },
  { to: "/balances", key: "nav.balances" },
  { to: "/activity", key: "nav.activity" },
  { to: "/redteam", key: "nav.redteam" },
];

export function App() {
  const { t, i18n } = useTranslation();
  const setLang = (lng: string) => {
    i18n.changeLanguage(lng);
    localStorage.setItem("lang", lng);
    document.documentElement.lang = lng;
  };

  return (
    <div className="min-h-screen">
      {/* the "Simulated" banner is fixed on every page and never dismissible (design.md §4) */}
      <div className="bg-sim px-4 py-1.5 text-center text-sm text-white" role="note">
        {t("app.banner")}
      </div>
      <div className="mx-auto flex max-w-[1280px] gap-6 p-4 md:p-8">
        <nav className="hidden w-[200px] shrink-0 md:block" aria-label="Primary">
          <ul className="flex flex-col gap-1">
            {NAV.map((n) => (
              <li key={n.to}>
                <NavLink
                  to={n.to}
                  className={({ isActive }) =>
                    `block rounded-control px-3 py-2 ${isActive ? "bg-surface font-medium" : "text-ink-muted"}`
                  }
                >
                  {t(n.key)}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="min-w-0 flex-1">
          <div className="mb-4 flex justify-end gap-2 text-sm" aria-label="Language">
            <button
              className={`rounded px-2 py-1 ${i18n.language === "en" ? "bg-surface font-medium" : "text-ink-muted"}`}
              onClick={() => setLang("en")}
            >
              EN
            </button>
            <button
              className={`rounded px-2 py-1 ${i18n.language === "bn" ? "bg-surface font-medium" : "text-ink-muted"}`}
              lang="bn"
              onClick={() => setLang("bn")}
            >
              বাংলা
            </button>
          </div>
          <main>
            <Outlet />
          </main>
        </div>
      </div>
      {/* mobile bottom tab bar */}
      <nav className="fixed bottom-0 left-0 right-0 flex justify-around border-t border-line bg-surface md:hidden" aria-label="Primary">
        {NAV.slice(0, 4).map((n) => (
          <NavLink key={n.to} to={n.to} className="flex-1 py-3 text-center text-sm">
            {t(n.key)}
          </NavLink>
        ))}
      </nav>
    </div>
  );
}
