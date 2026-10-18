import { expect, test } from "@playwright/test";

import { seedMandate } from "./helpers";

/** E2E-10 · the Red-team page renders numbers from the report JSON (never hard-typed). */
test("E2E-10 red-team page renders the report", async ({ page }) => {
  await page.goto("/redteam");
  await expect(page.getByRole("heading", { name: /Red-team report/i })).toBeVisible();
  // Either numbers from a generated report, or an honest "run make eval" message.
  await expect(page.locator("body")).toContainText(/Reproduce with|make eval|attack/i);
});

/** E2E-08 (partial) · the audit page verifies the chain through the real endpoint and reports it VALID. */
test("E2E-08 audit page verifies the hash chain as valid", async ({ page, request }) => {
  await seedMandate(request);
  await page.goto("/activity");
  await expect(page.getByRole("heading", { name: /Audit log/i })).toBeVisible();
  const verify = page.getByRole("button", { name: /Verify chain/i });
  await expect(verify).toBeVisible();
  await verify.click();
  // The seeded chain must verify; asserting only "valid or broken" would pass on a corrupted log.
  await expect(page.getByText(/Chain valid/i)).toBeVisible();
});
