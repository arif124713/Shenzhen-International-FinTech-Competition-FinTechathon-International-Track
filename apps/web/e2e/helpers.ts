import { expect, type APIRequestContext, type Page } from "@playwright/test";

/** Shared E2E helpers. All flows use the seeded demo state and the offline replay LLM. */

export const API = "http://127.0.0.1:8000/api/v1";

/** A clear English rule the offline replay compiler has a fixture for (see eval/fixtures_gen.py). */
export const CLEAR_RULE_EN = "pay tuition only to my university up to 5000, new payees need ammu approval";

/** Reset the demo runtime to its seeded state (demo mode only), then activate a mandate for Rafi. */
export async function seedMandate(request: APIRequestContext): Promise<number> {
  await request.post(`${API}/admin/reset`);
  const compiled = await request.post(`${API}/mandates/compile`, {
    data: { text: CLEAR_RULE_EN, lang: "en" },
  });
  expect(compiled.ok()).toBeTruthy();
  const body = await compiled.json();
  expect(body.status).toBe("ok");
  const confirmed = await request.post(`${API}/mandates/confirm`, {
    data: { body: body.candidate, back_translation: body.back_translation },
  });
  expect(confirmed.ok()).toBeTruthy();
  return (await confirmed.json()).version as number;
}

/** Assert the simulated banner is present (design.md §4: visible on every page). */
export async function expectSimulatedBanner(page: Page): Promise<void> {
  await expect(page.getByRole("note")).toContainText(/Simulated|সিমুলেটেড/);
}
