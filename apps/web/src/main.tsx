import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, Navigate, RouterProvider } from "react-router-dom";
import { App } from "./App";
import { Activity } from "./pages/Activity";
import { Balances } from "./pages/Balances";
import { Dashboard } from "./pages/Dashboard";
import { Guardian } from "./pages/Guardian";
import { Login } from "./pages/Login";
import { Mandate } from "./pages/Mandate";
import { Pay } from "./pages/Pay";
import { RedTeam } from "./pages/RedTeam";
import { RegistryPage } from "./pages/RegistryPage";
import { initI18n } from "./i18n";
import "./styles/tokens.css";

initI18n();

const router = createBrowserRouter([
  { path: "/approve/:token", element: <Guardian /> },
  { path: "/login", element: <Login onLogin={() => (window.location.href = "/")} /> },
  {
    path: "/",
    element: <App />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "pay", element: <Pay /> },
      { path: "mandate", element: <Mandate /> },
      { path: "balances", element: <Balances /> },
      { path: "activity", element: <Activity /> },
      { path: "redteam", element: <RedTeam /> },
      { path: "registry", element: <RegistryPage /> },
      { path: "*", element: <Navigate to="/" replace /> },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>
);
