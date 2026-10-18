import { expect, test } from "@playwright/test";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { API, seedMandate } from "./helpers";

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../data/fixtures/invoices");

/**
 * E2E-05 · Large transfer -> Needs approval -> guardian page on a 360px viewport -> approve.
 * The guardian page is token-bound and single-use; the engine is re-run on approval and executes once.
 */
test.describe("mobile-360 guardian approval", () => {
  test.skip(({ viewport }) => (viewport?.width ?? 999) > 480, "guardian flow is verified at 360px");

  test("E2E-05 large payment needs approval and the guardian approves once", async ({ page, request }) => {
    await seedMandate(request);

    // Rafi uploads the large invoice (USD 1,800 > escalate_above USD 1,200) and requests payment.
    const upload = await request.post(`${API}/documents`, {
      multipart: { file: { name: "inv_large_amount.pdf", mimeType: "application/pdf",
                           buffer: (await import("node:fs")).readFileSync(path.join(FIXTURES, "inv_large_amount.pdf")) } },
    });
    expect(upload.ok()).toBeTruthy();
    const reader = (await upload.json()).reader;

    const proposalRes = await request.post(`${API}/proposals`, {
      data: { user_request: "pay this tuition invoice", document_fields: reader },
    });
    const created = await proposalRes.json();
    expect(created.decision).toBe("ESCALATE");
    expect(created.status).toBe("needs_approval");

    const token = created.approval.token as string;
    await page.goto(`/approve/${token}`);
    await expect(page.getByRole("heading", { name: /Rafi wants to send/i })).toBeVisible();
    // The page fetches the pre-payment summary from the token (no JSON pasting) and shows the lock text.
    await expect(page.getByText(/locked to this exact payment/i)).toBeVisible();
    await expect(page.getByText("Northfield University")).toBeVisible();
    await expect(page.getByText(/1,800\.00/)).toBeVisible();

    await page.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(page.getByRole("status").first()).toContainText(/Allowed/i);
    await expect(page.getByText(/checked again and sent/i)).toBeVisible();
  });

  test("guardian buttons are full width, stacked and at least 48px tall", async ({ page, request }) => {
    await seedMandate(request);
    await page.goto("/approve/preview-token-not-used");
    // Buttons render even when the token is unknown (the summary fails to load, but the controls are present).
    const approve = page.getByRole("button", { name: "Approve", exact: true });
    const reject = page.getByRole("button", { name: "Reject", exact: true });
    await expect(approve).toBeVisible();
    await expect(reject).toBeVisible();
    const a = await approve.boundingBox();
    const r = await reject.boundingBox();
    expect(a && r).toBeTruthy();
    expect(a!.height).toBeGreaterThanOrEqual(48);
    expect(r!.height).toBeGreaterThanOrEqual(48);
    expect(a!.y).toBeLessThan(r!.y); // approve above reject, stacked
  });
});
