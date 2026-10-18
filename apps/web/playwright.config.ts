import { defineConfig, devices } from "@playwright/test";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const venvPy = path.join(repoRoot, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
const python = existsSync(venvPy) ? venvPy : "python";

/**
 * E2E config (testing.md §7). Boots the real API (:8000) and the Vite dev server (:5173),
 * which proxies /api to the API. All runs use the offline replay LLM, so no network is needed.
 */
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 7_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile-360", use: { ...devices["Pixel 5"], viewport: { width: 360, height: 800 } } },
  ],
  webServer: [
    {
      // Run the real API from the repo root (module `api.main` lives under apps/, on PYTHONPATH).
      command: `"${python}" -m uvicorn api.main:app --port 8000 --host 127.0.0.1`,
      cwd: repoRoot,
      url: "http://127.0.0.1:8000/api/v1/health",
      reuseExistingServer: true,
      timeout: 90_000,
      env: { LLM_PROVIDER: "replay", PYTHONPATH: "packages;services;apps;." },
    },
    {
      command: "npm run dev -- --host 127.0.0.1 --port 5173",
      cwd: here,
      url: "http://127.0.0.1:5173",
      reuseExistingServer: true,
      timeout: 90_000,
    },
  ],
});
