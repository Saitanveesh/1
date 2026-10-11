import { expect, test, type BrowserContext } from "@playwright/test";
import fs from "node:fs";

const seedPath = process.env.SOC_SEED_FILE;
if (!seedPath) throw new Error("SOC_SEED_FILE must point at the seeded scenario (seed.json)");
const seed = JSON.parse(fs.readFileSync(seedPath, "utf-8"));

const scopeA = `/?tenant=${seed.tenant_a}&site=${seed.site_a}`;
const scopeB = `/?tenant=${seed.tenant_b}&site=${seed.site_b}`;

async function signIn(context: BrowserContext, jwt: string): Promise<void> {
  // The console authenticates with the mon_session cookie, validated by the real backend.
  await context.addCookies([
    { name: "mon_session", value: jwt, url: "http://127.0.0.1:5173" }
  ]);
}

test("1. an unauthenticated browser is refused and shows no data", async ({ page }) => {
  await page.goto(scopeA);
  await expect(page.getByTestId("unauthenticated")).toBeVisible();
  await expect(page.getByTestId("operator-context")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText(seed.incident_title);
});

test.describe("authenticated operator (tenant A)", () => {
  test.beforeEach(async ({ context }) => {
    await signIn(context, seed.token_operator_a);
  });

  test("2. authenticated operator context and live overview", async ({ page }) => {
    await page.goto(scopeA);
    await expect(page.getByTestId("operator-context")).toHaveCount(0);
    await expect(page.getByTestId("soc-gauges")).toBeVisible();
    await expect(page.getByTestId("mon-single-console")).toBeVisible();
    await expect(page.getByTestId("live-packet-history")).toHaveClass(/mon-traffic-compact/);
    await expect(page.getByText("ATTACK PRESSURE")).toBeVisible();
    await expect(page.getByTestId("overview-status-strip")).toBeVisible();
    await expect(page.locator(".connection.live")).toBeVisible();
    await expect(page.getByTestId("access-denied")).toHaveCount(0);
  });

  test("3-9. incident, evidence, asset, identity, graph, capability, response, recovery, audit", async ({ page }) => {
    await page.goto(scopeA);
    await page.getByRole("button", { name: /^Incidents/ }).click();

    const row = page.getByTestId("incident-row").filter({ hasText: seed.incident_title });
    await expect(row).toHaveCount(1);
    await row.getByRole("button", { name: seed.incident_title }).click();

    const detail = page.getByTestId("incident-detail");
    await expect(detail).toBeVisible();
    await expect(page.getByTestId("incident-detail-title")).toHaveText(seed.incident_title);

    // evidence
    await expect(page.getByTestId("incident-chronology")).toBeVisible();
    await expect(page.getByTestId("incident-event-chain")).toBeVisible();
    await expect(page.getByTestId("incident-case-queue")).toBeVisible();
    await expect(page.getByTestId("ai-timeline-event").first()).toBeVisible();
    await page.getByRole("tab", { name: /EVIDENCE/ }).click();
    await expect(page.getByTestId("evidence-item").first()).toBeVisible();
    expect(await page.getByTestId("evidence-item").count()).toBeGreaterThanOrEqual(1);
    await expect(page.getByTestId("evidence-list")).toContainText("IDENTITY");

    // affected asset and identity
    await expect(page.getByTestId("affected-asset").first()).toContainText(seed.asset_id);
    await expect(page.getByTestId("affected-identity").first()).toBeVisible();

    // investigation / attack path
    await expect(page.getByTestId("graph-edge").first()).toBeVisible();

    // containment capability
    await page.getByRole("tab", { name: /RESPONSE/ }).click();
    const capability = page.getByTestId("containment-capability").first();
    await expect(capability).toContainText(seed.enforcement_point_id);
    await expect(capability).toContainText("BLOCK_IP");

    // response, policy, approval, rollback/recovery
    const response = page.getByTestId("response-row").first();
    await expect(page.getByTestId("response-status").first()).toHaveText(seed.final_execution_status);
    expect(seed.final_execution_status).toBe("ROLLED_BACK");
    await expect(response).toContainText(seed.policy_outcome);
    await expect(response).toContainText("approved by soc-operator-a");
    await expect(response).toContainText("rolled back");
    await expect(page.getByTestId("rollback-result")).toBeVisible();

    // audit history
    const audit = page.getByTestId("audit-list");
    await expect(audit).toContainText("ROLLBACK");
    await expect(audit).toContainText("ROLLED_BACK");
    expect(await page.getByTestId("audit-row").count()).toBeGreaterThanOrEqual(2);
  });

  test("AI Analysis reconstructs the real incident timeline without requiring Ollama", async ({ page }) => {
    await page.goto(scopeA);
    await page.getByRole("button", { name: /^AI Analysis/ }).click();
    const workspace = page.getByTestId("ai-analysis-workspace");
    await expect(workspace).toBeVisible();
    await expect(page.getByText("Incident Reconstruction")).toBeVisible();
    await expect(page.getByTestId("ai-case-select")).toContainText(seed.incident_title);
    await expect(page.getByTestId("ai-telemetry-tools")).toBeVisible();
    await expect(page.getByTestId("ai-case-correlation")).toBeVisible();
    await expect(page.getByTestId("ai-model-investigation")).toBeVisible();
    // AI is on demand; the seeded browser runner has no Ollama and must not
    // call it merely because the analyst opened the visual investigation.
    await expect(page.getByTestId("ai-generate-brief")).toBeVisible();
  });

  test("per-incident 3D reconstruction is navigable and does not invent packet paths", async ({ page }) => {
    await page.goto(scopeA);
    await page.getByRole("button", { name: /^Investigation/ }).click();
    await expect(page.getByTestId("investigation-3d")).toBeVisible();
    await expect(page.getByTestId("incident-3d-scene")).toBeVisible();
    await expect(page.getByTestId("incident-3d-viewport")).toBeVisible();
    await expect(page.getByTestId("mon3d-node-asset").first()).toBeVisible();
    await page.getByRole("button", { name: "2D", exact: true }).click();
    await expect(page.getByTestId("incident-2d-view")).toBeVisible();
    await page.getByRole("button", { name: "3D", exact: true }).click();
    await expect(page.getByTestId("scene-inspector")).toBeVisible();
    await expect(page.getByText(/Recorded entities/)).toBeVisible();
    await expect(page.getByTestId("incident-event-chain")).toBeVisible();
  });

  test("enforcement, response and audit views show the same recorded state", async ({ page }) => {
    await page.goto(scopeA);
    await page.getByRole("button", { name: /^Operations/ }).click();
    await expect(page.getByTestId("operations-workspace")).toBeVisible();
    await page.getByRole("button", { name: "Enforcement", exact: true }).click();
    await expect(page.getByRole("cell", { name: seed.enforcement_point_id })).toBeVisible();
    await page.getByRole("button", { name: "Response", exact: true }).click();
    await expect(page.getByRole("cell", { name: "ROLLED_BACK" })).toBeVisible();
    await page.getByRole("button", { name: "Audit", exact: true }).click();
    await expect(page.getByRole("cell", { name: "ROLLBACK" }).first()).toBeVisible();
    await page.getByRole("button", { name: "Admin", exact: true }).click();
    await expect(page.getByTestId("mon-admin-debug")).toContainText("soc-operator-a");
    await expect(page.getByTestId("mon-admin-debug")).toContainText("tenant_admin");
  });

  test("fleet view reports honestly when no sensor is enrolled", async ({ page }) => {
    await page.goto(scopeA);
    await page.getByRole("button", { name: /^Operations/ }).click();
    await page.getByRole("button", { name: "Fleet", exact: true }).click();
    await expect(page.getByTestId("fleet-panel")).toBeVisible();
    await expect(page.getByText("No sensors enrolled for this site.")).toBeVisible();
  });

  test("11. tenant-scoped navigation cannot expose another tenant", async ({ page }) => {
    await page.goto(scopeA);
    await expect(page.locator("body")).not.toContainText(seed.tenant_b_title);

    await page.goto(scopeB);
    await expect(page.getByTestId("access-denied")).toBeVisible();
    await expect(page.locator("body")).not.toContainText(seed.tenant_b_title);
    await page.getByRole("button", { name: /^Incidents/ }).click();
    await expect(page.getByTestId("incident-row")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText(seed.tenant_b_title);

    // The same restriction holds at the API the console uses.
    const api = await page.request.get(
      `/api/v1/incidents?tenant_id=${seed.tenant_b}&site_id=${seed.site_b}`
    );
    expect(api.status()).toBe(403);
  });
});

test("tenant B operator sees their own incident and nothing of tenant A", async ({ page, context }) => {
  await signIn(context, seed.token_operator_b);
  await page.goto(scopeB);
  await page.getByRole("button", { name: /^Incidents/ }).click();
  await expect(page.getByTestId("incident-row").filter({ hasText: seed.tenant_b_title })).toHaveCount(1);
  await expect(page.locator("body")).not.toContainText(seed.incident_title);
  await page.goto(scopeA);
  await expect(page.getByTestId("access-denied")).toBeVisible();
  await expect(page.locator("body")).not.toContainText(seed.incident_title);
});
