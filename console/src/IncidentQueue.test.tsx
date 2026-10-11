import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import IncidentQueue from "./IncidentQueue";
import type { Incident } from "./types";

const one: Incident = {
  incident_id: "pc6-auth", tenant_id: "mon-lab", site_id: "site-a",
  title: "Repeated endpoint authentication failures", severity: "MEDIUM",
  status: "OPEN", confidence: .72, affected_asset_ids: ["linux-host:lab-pc5"],
  detector_ids: ["endpoint-auth-failure-pressure"],
  entities: ["linux-host:lab-pc5", "10.77.0.60"],
  last_seen: "2026-10-11T09:00:00Z"
};
const two: Incident = {
  ...one, incident_id: "pc2-auth", entities: ["10.77.0.1"],
  last_seen: "2026-10-11T08:59:00Z"
};
afterEach(cleanup);
it("selects each real case without scaling down the whole page", () => {
  const choose = vi.fn();
  render(<IncidentQueue incidents={[two, one]} selectedId="pc6-auth" onSelect={choose} />);
  const rows = screen.getAllByTestId("incident-row");
  expect(rows).toHaveLength(2);
  expect(within(rows[0]).getByText("10.77.0.60")).toBeTruthy();
  expect(rows[0].querySelector("button")?.getAttribute("aria-pressed")).toBe("true");
  fireEvent.click(within(rows[1]).getByRole("button"));
  expect(choose).toHaveBeenCalledWith(two);
});
it("does not invent case records", () => {
  render(<IncidentQueue incidents={[]} selectedId={null} onSelect={vi.fn()} />);
  expect(screen.getByText("No incidents recorded at this site.")).toBeTruthy();
});
