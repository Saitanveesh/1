import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Stage4ResponsePanel, { eligibleForManualContainment, impactAfterBlock,
  type VictimImpact, type MitigationStatus } from "./Stage4ResponsePanel";
import type { SecurityThreatAlert } from "./securityAlerts";

const at=new Date().toISOString();
const alert:SecurityThreatAlert={
  key:"ids:"+at+"|42000501|MON lab traversal|10.77.0.70|42000|10.77.0.50|8085",
  source:"10.77.0.70",target:"10.77.0.50",signatureId:42000501,
  title:"Training canary attempted",severity:"HIGH",attackClass:"web",
  observedAt:at,detector:"Suricata IDS"
};
const mitigation:MitigationStatus={
  source:"10.77.0.70",destination:"10.77.0.50",port:8085,active:false,
  expires_in_seconds:null,enforcement:"NO_RULE",audit:[],
  scope:"PC2 forward only"
};
const impact:VictimImpact={
  status:"OBSERVED",source:"10.77.0.70",window_start:at,window_end:at,
  observed_requests:3,successful_http_responses:3,
  fictional_exposure_responses:2,fictional_records_in_responses:2,
  fictional_response_bytes_written:242,
  exposure_categories:{fictional_canary:1,fictional_student:1,fictional_internal_notices:0},
  last_fictional_exposure_at:at,
  recent_events:[{
    at,source:"10.77.0.70",route:"/download",http_status:200,
    response_bytes_written:120,fictional_exposure:"fictional_canary",
    fictional_records:1
  }],
  truncated:false,scope:"Fictional data only"
};

function setup(status:MitigationStatus=mitigation, response:VictimImpact=impact) {
  const fetcher=vi.fn(async (url:string, options?:RequestInit) => ({
    ok:true,status:200,json:async () =>
      options?.method === "POST" ? {
        ...status,active:!status.active,enforcement:"KERNEL_RULE_PRESENT"
      } : url.includes("/mitigation?") ? status : response
  }));
  vi.stubGlobal("fetch",fetcher);
  return fetcher;
}

afterEach(()=>{cleanup();vi.unstubAllGlobals();vi.restoreAllMocks();});

describe("Stage 4 operator mitigation and victim impact",()=>{
  it("accepts only a supported real lab alert and not a generic finding",()=>{
    expect(eligibleForManualContainment(alert)).toBe(true);
    expect(eligibleForManualContainment({...alert,source:"10.77.0.1"})).toBe(false);
    expect(eligibleForManualContainment({...alert,signatureId:999})).toBe(false);
    expect(eligibleForManualContainment({...alert,key:"finding:2"})).toBe(false);
  });
  it("exposes real fictional application outcomes, never financial or real-data loss",async ()=>{
    setup();
    render(<Stage4ResponsePanel alert={alert}/>);
    await waitFor(()=>expect(screen.getByText("242")).toBeTruthy());
    expect(screen.getByText("fictional exposure responses")).toBeTruthy();
    expect(screen.getByText("2")).toBeTruthy();
    expect(screen.getByText(/No active training-web block/)).toBeTruthy();
    fireEvent.click(screen.getByText("Evidence and response history"));
    expect(screen.getByText(/not applicable to the fictional training fixtures/)).toBeTruthy();
  });
  it("requires explicit operator approval and exact target before POST",async ()=>{
    const fetcher=setup();
    render(<Stage4ResponsePanel alert={alert}/>);
    await waitFor(()=>expect(screen.getByRole("button",{name:"Block this source temporarily"})).toBeTruthy());
    fireEvent.click(screen.getByRole("button",{name:"Block this source temporarily"}));
    const apply=screen.getByRole("button",{name:"Apply timed block"});
    expect(apply.hasAttribute("disabled")).toBe(true);
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(apply);
    await waitFor(()=>expect(fetcher.mock.calls.some(([url,opts]) =>
      url === "/portal/stage4/block" && opts?.method === "POST")).toBe(true));
    const posted=fetcher.mock.calls.find(([url])=>url==="/portal/stage4/block");
    expect(JSON.parse(posted?.[1]?.body as string)).toMatchObject({
      source:"10.77.0.70",alert_key:alert.key,duration_seconds:120
    });
  });
  it("refuses containment for non-enrolled source",async ()=>{
    const fetcher=setup();
    render(<Stage4ResponsePanel alert={{...alert,source:"10.77.0.80" }}/>);
    expect(screen.getByText(/restricted to verified activity/)).toBeTruthy();
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("compares only retained actual post-block victim events",()=>{
    expect(impactAfterBlock(impact,[])).toBeNull();
    expect(impactAfterBlock(impact,[{
      at:new Date(Date.parse(at)-1000).toISOString(),
      source:"10.77.0.70",destination:"10.77.0.50",port:8085,
      action:"block",active:true,rule_state:"KERNEL_RULE_PRESENT"
    }])).toEqual({requests:1,exposures:1});
  });
});
