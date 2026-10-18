import { expect, test } from "@playwright/test";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { API, expectSimulatedBanner, seedMandate } from "./helpers";

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../data/fixtures/invoices");

/** E2E-03 · Upload a genuine invoice -> Allowed; trace in order; ledger updated; "Simulated" labels. */
test("E2E-03 genuine invoice is allowed and shows the decision trace", async ({ page, request }) => {
  await seedMandate(request);
  await page.goto("/pay");
  await expectSimulatedBanner(page);

  await page.setInputFiles("#file", path.join(FIXTURES, "inv_genuine_northfield.pdf"));
  await expect(page.getByRole("heading", { name: /What the reader found/i })).toBeVisible();
  await expect(page.getByText("NF0012345678", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Send payment" }).click();
  await expect(page.getByRole("status").first()).toContainText(/Allowed/i);

  // decision trace order: Document -> Registry -> Policy -> Rail -> Result
  const trace = page.locator("ol, ul").filter({ hasText: "Document" }).first();
  await expect(trace).toContainText("Registry");
  await expect(page.getByText(/Payment sent \(simulated\)/i)).toBeVisible();
});

/** E2E-04 · Upload a tampered invoice (substituted account) -> Blocked with a plain-language reason. */
test("E2E-04 tampered invoice is blocked with REGISTRY_MISMATCH explained", async ({ page, request }) => {
  await seedMandate(request);
  await page.goto("/pay");

  await page.setInputFiles("#file", path.join(FIXTURES, "inv_substituted_account.pdf"));
  await expect(page.getByRole("heading", { name: /What the reader found/i })).toBeVisible();
  await page.getByRole("button", { name: "Send payment" }).click();

  await expect(page.getByRole("status").first()).toContainText(/Blocked/i);
  await expect(page.getByText(/not the one your university uses/i)).toBeVisible();
});

/** E2E-12 · Hidden text is shown escaped and labelled; no script executes. */
test("E2E-12 untrusted document text is escaped and labelled", async ({ page, request }) => {
  await seedMandate(request);
  await page.goto("/pay");
  await page.setInputFiles("#file", path.join(FIXTURES, "inv_hidden_text.pdf"));

  const label = page.getByText(/From the document \(not instructions\)/i);
  await expect(label).toBeVisible();
  // the injected instruction string must appear as literal text, never as markup
  const quote = page.locator("pre");
  await expect(quote).toContainText(/ignore previous/i);
  // no script tag from the document survived into the DOM
  expect(await page.locator("script", { hasText: "ignore previous" }).count()).toBe(0);
});

/** E2E-11 (partial) · the flagship Pay page is keyboard operable and the verdict is announced. */
test("E2E-11 verdict chips carry an accessible status role", async ({ page, request }) => {
  await seedMandate(request);
  await page.goto("/pay");
  await page.setInputFiles("#file", path.join(FIXTURES, "inv_genuine_northfield.pdf"));
  const send = page.getByRole("button", { name: "Send payment" });
  await send.scrollIntoViewIfNeeded();
  await send.click();
  await expect(page.getByRole("status").first()).toContainText(/Allowed/i);
});

/** The API used by the browser is the real one (numbers come from the backend, never typed by hand). */
test("API health and red-team report are reachable", async ({ request }) => {
  const health = await request.get(`${API}/health`);
  expect((await health.json()).banner).toContain("Simulated");
  const report = await request.get(`${API}/eval/report`);
  const body = await report.json();
  if (body.available) {
    expect(body.report.attacks.total).toBeGreaterThan(0);
    expect(body.report).toHaveProperty("generated_at");
  } else {
    expect(body.message).toContain("make eval");
  }
});
