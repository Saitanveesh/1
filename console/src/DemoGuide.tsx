import { useEffect, useMemo, useState } from "react";
import type { SecurityThreatAlert } from "./securityAlerts";
import { isProtectedCaptureReady, isRecentObservation } from "./operationalTruth";
import type { Incident, PacketCaptureSnapshot, SuricataSnapshot } from "./types";
import type { MitigationStatus, VictimImpact } from "./Stage4ResponsePanel";
import "./DemoGuide.css";

export type GuideView = "Overview" | "Alerts" | "Incidents" | "Investigation";

type Evidence = {
  view: GuideView;
  connected: boolean;
  capture: PacketCaptureSnapshot | null;
  sensor: SuricataSnapshot | null;
  sensorAvailable: boolean;
  alerts: SecurityThreatAlert[];
  acknowledged: Record<string, string>;
  focusedAlert: SecurityThreatAlert | null;
  cases: Incident[];
  mitigation: MitigationStatus | null;
  impact: VictimImpact | null;
  now?: number;
};

export type GuideStep = {
  id: string;
  title: string;
  detail: string;
  status: "seen" | "in-progress" | "waiting" | "unavailable";
};

export type GuideStory = {
  heading: string;
  explanation: string;
  pageHelp: string;
  steps: GuideStep[];
  source: string | null;
  observedAt: string | null;
  coverage: string;
};

export function preferredGuideAlert(input: Pick<Evidence, "focusedAlert" | "alerts" | "capture">):
SecurityThreatAlert | null {
  const protectedIp = input.capture?.protected_host_ip;
  if (!protectedIp) return null;
  if (input.focusedAlert?.target === protectedIp) return input.focusedAlert;
  return input.alerts.find(item => item.target === protectedIp) ?? null;
}

function observedPackets(capture: PacketCaptureSnapshot | null, now: number): boolean {
  if (!isProtectedCaptureReady(capture, now)) return false;
  const last = capture?.protected_route_samples?.slice(-10) ?? [];
  return last.some(item => item.packets > 0);
}

const pageHelp: Record<GuideView, string> = {
  Overview: "This is the overall picture. It shows monitored traffic, sensors and recent security activity.",
  Alerts: "An alert means a monitoring rule noticed something unusual. It does not prove an attack succeeded.",
  Incidents: "Cases group security findings and recorded actions for an operator to review.",
  Investigation: "The Blue Team examines the evidence before deciding whether a response is necessary."
};

export function describeDemo(input: Evidence): GuideStory {
  const now = input.now ?? Date.now();
  const alert = preferredGuideAlert(input);
  const source = alert?.source ?? null;
  const freshAlert = alert && isRecentObservation(alert.observedAt, now, 120_000) ? alert : null;
  const captureReady = isProtectedCaptureReady(input.capture, now);
  const traffic = observedPackets(input.capture, now);
  const idsActive = input.sensorAvailable && input.sensor?.service_state === "active";
  const confirmedRule = Boolean(
    source && input.mitigation?.source === source &&
    input.mitigation.active && input.mitigation.enforcement === "KERNEL_RULE_PRESENT"
  );
  const victim = source && input.impact?.source === source ? input.impact : null;
  const decisions = source && input.mitigation?.source === source ? input.mitigation?.audit ?? [] : [];
  const blockRecorded = decisions.some(item => item.action === "block");
  const reviewRecorded = Boolean(alert && input.acknowledged[alert.key]);
  const investigating = Boolean(input.view === "Investigation" && input.focusedAlert);
  const recordedResponses = victim?.observed_requests ?? 0;
  const fakeExposure = victim?.fictional_exposure_responses ?? 0;

  let heading = "Waiting for an observed training event";
  let explanation = "We are ready to explain the demonstration. No current attack has been confirmed by the information available here.";
  if (!captureReady && !idsActive && !input.connected) {
    heading = "Monitoring information is unavailable";
    explanation = "The live feed and sensor coverage could not be confirmed. We will not show a made-up attack.";
  } else if (confirmedRule) {
    heading = "A temporary website block is installed";
    explanation = "The gateway reports a real firewall rule against the selected source. A new request from the testing computer must still be tried to prove it was stopped.";
  } else if (investigating && alert) {
    heading = "The Blue Team is checking the alert";
    explanation = "This investigation screen shows what the sensors recorded. Opening an alert does not mean the attacker has been stopped.";
  } else if (freshAlert) {
    heading = "Suspicious activity was reported";
    explanation = "A recent security alert points to the training website. The team can inspect the evidence and decide what to do.";
  } else if (fakeExposure > 0) {
    heading = "The training website returned fictional data";
    explanation = "The victim recorded responses containing fake training records. These counts do not prove that a remote computer received the data.";
  } else if (traffic) {
    heading = "Traffic is passing through the monitored network";
    explanation = "The gateway measured packets on the protected path. Normal traffic is not automatically an attack.";
  } else if (captureReady) {
    heading = "Watching for traffic to the training website";
    explanation = "The monitored path is ready, but the current measurement window does not show packet activity.";
  }

  const steps: GuideStep[] = [
    {
      id: "traffic", title: "1. Network activity",
      status: traffic ? "seen" : captureReady ? "waiting" : "unavailable",
      detail: traffic ? "The gateway measured traffic to the protected website." :
        captureReady ? "The path is monitored; waiting for a packet observation." :
          "A verified protected-route capture is not available."
    },
    {
      id: "detection", title: "2. Suspicious pattern",
      status: freshAlert ? "seen" : idsActive ? "waiting" : "unavailable",
      detail: freshAlert ? "A recent detection was recorded for the website." :
        idsActive ? "Threat detection is running; no recent matching alert shown." :
          "Threat detection is offline or not verified."
    },
    {
      id: "review", title: "3. Blue Team review",
      status: reviewRecorded ? "seen" : investigating ? "in-progress" : "waiting",
      detail: reviewRecorded ? "An operator acknowledged the selected alert." :
        investigating ? "The selected alert is open for investigation." :
          "An operator has not acknowledged the selected alert."
    },
    {
      id: "block", title: "4. Optional protection",
      status: confirmedRule ? "seen" : blockRecorded ? "in-progress" : "waiting",
      detail: confirmedRule ? "A time-limited firewall rule is reported in the gateway." :
        blockRecorded ? "A previous block is recorded, but no active block is verified now." :
          "No verified temporary block for this selected source."
    },
    {
      id: "outcome", title: "5. Website response",
      status: victim ? "seen" : "unavailable",
      detail: victim
        ? (recordedResponses + " responses recorded by the website; " + fakeExposure +
           " contained fictional training data.")
        : "Victim-side response information is not available for the selected source."
    }
  ];

  return {
    heading, explanation, pageHelp: pageHelp[input.view], steps,
    source, observedAt: alert?.observedAt ?? null,
    coverage: confirmedRule ? "Rule installed — verify from the attacker computer" :
      victim ? "Victim record available — fictional test data only" :
        idsActive ? "Monitoring evidence available; victim outcome not confirmed" :
          "Limited evidence — not a simulated result"
  };
}

type Props = Omit<Evidence, "mitigation" | "impact"> & {
  authenticated: boolean;
  onClose: () => void;
};

const possibleSources = new Set(["10.77.0.60", "10.77.0.70"]);

export default function DemoGuide(props: Props) {
  const alert = preferredGuideAlert(props);
  const source = alert && possibleSources.has(alert.source) && alert.target === "10.77.0.50"
    ? alert.source : null;
  const [result, setResult] = useState<{
    source: string;
    mitigation: MitigationStatus | null;
    impact: VictimImpact | null;
  } | null>(null);

  useEffect(() => {
    let stopped = false;
    if (!props.authenticated || !source) return;
    const alertAt = alert?.observedAt;
    async function poll(): Promise<void> {
      const s = source as string;
      const encode = encodeURIComponent(s);
      const get = async <T,>(url: string): Promise<T> => {
        const response = await fetch(url, { credentials: "same-origin", cache: "no-store" });
        if (!response.ok) throw new Error("Evidence unavailable");
        return response.json() as Promise<T>;
      };
      const queries = await Promise.allSettled([
        get<MitigationStatus>("/portal/stage4/mitigation?source=" + encode),
        get<VictimImpact>("/portal/stage4/impact?source=" + encode +
          (alertAt ? "&since=" + encodeURIComponent(alertAt) : ""))
      ]);
      if (stopped) return;
      const mitigation = queries[0].status === "fulfilled" &&
        queries[0].value.source === s ? queries[0].value : null;
      const impact = queries[1].status === "fulfilled" &&
        queries[1].value.source === s ? queries[1].value : null;
      setResult({ source: s, mitigation, impact });
    }
    void poll();
    const timer = window.setInterval(() => { void poll(); }, 5000);
    return () => { stopped = true; window.clearInterval(timer); };
  }, [props.authenticated, source, alert?.observedAt]);

  const story = useMemo(() => describeDemo({
    ...props,
    mitigation: result?.source === source ? result.mitigation : null,
    impact: result?.source === source ? result.impact : null
  }), [props, result, source]);

  return <aside className="mon-demo-guide" aria-label="What is happening in this demonstration"
    data-testid="batch5-plain-language-panel">
    <div className="mon-demo-guide-header">
      <div>
        <span className="mon-demo-guide-kicker">PLAIN-LANGUAGE GUIDE</span>
        <h2>What's happening?</h2>
      </div>
      <button type="button" className="mon-demo-guide-close" onClick={props.onClose}
        aria-label="Hide explanation panel">×</button>
    </div>
    <div className="mon-demo-guide-body">
      <p className="mon-demo-guide-page">{story.pageHelp}</p>
      <section className="mon-demo-guide-current" aria-live="polite" aria-atomic="true">
        <span className="mon-demo-guide-kicker">CURRENTLY</span>
        <h3>{story.heading}</h3>
        <p>{story.explanation}</p>
      </section>
      <div className="mon-demo-guide-small-head">
        <h3>Follow the demonstration</h3>
        <span>Based on recorded data</span>
      </div>
      <ol className="mon-demo-guide-steps">
        {story.steps.map(step =>
          <li className={"mon-demo-guide-step status-" + step.status} key={step.id}>
            <span className="mon-demo-guide-indicator" aria-hidden="true"/>
            <div><strong>{step.title}</strong><p>{step.detail}</p></div>
          </li>
        )}
      </ol>
      <div className="mon-demo-guide-evidence">
        <strong>What can we confirm?</strong>
        <p>{story.coverage}</p>
        {story.source && <p>Source reported: <code>{story.source}</code></p>}
        <p className="mon-demo-guide-limits">All exposed records are fictional training data.
          An alert is not proof of a successful attack; an installed block needs a fresh connectivity test.</p>
      </div>
    </div>
  </aside>;
}
