# MON final operator stage

This release is a **frontend-only** change built on top of the already operating
Batch 1 detection pipeline. It does not enroll WireGuard peers, change the PC-5
training app, restart the IDS, edit the MON database, or modify PC-6/PC-7.

## What changed for operators

The command portal has four clear sections:

1. **Dashboard** — current monitored traffic, alert count, open cases, health
   and clickable recent findings. Detailed network interface information is
   collapsed under **Network details**, not discarded.
2. **Alerts** — a searchable list of actual PC-5-targeted Suricata EVE
   signatures, MON stream notifications received during this browser session,
   and recent MON findings. Filter by **All**, **Needs review** and
   **Acknowledged**. Sort by time or severity. No demo rows are generated.
3. **Cases** — recorded MON incidents, readable timeline, evidence, response
   planning and rollback history. Selecting a case opens its actual MON case
   record. The optional generated summary is collapsed by default; it does
   not replace evidence.
4. **Investigation** — clicking **Investigate** on an alert opens the *same*
   alert's source, destination, signature, observation time, review status,
   and actual matching recent packet headers if they are still retained.
   **Overview** explains what happened, which evidence exists, and what a
   review means. **Captured evidence** shows the original sensor record and
   current AF_PACKET header samples. **Copy report** exports the recorded
   facts only. If an alert corresponds to a formal MON case, **Open related
   case** navigates there.

**Acknowledgment behavior**:
- A new Suricata signature can be acknowledged only while the PC-2 detection
  sensor is running, its exact record is retained and the server's 15-minute
  review window is open. A session-authenticated POST checks the real record
  against the configured protected destination before persisting the review
  timestamp in the PC-2 journal. The button shows the result.
- An old/offline Suricata record stays available for investigation but its
  review button explains why the server cannot accept a new acknowledgment.
- A MON-only stream/finding notification can be reviewed in the browser
  session. This **does not** pretend to update a central case or audit store.
- A rejected acknowledgment shows the server error, not a success animation.
- Acknowledgment **does not** block a source, close a case or prove a
  successful exploit. Formal containment still uses the separately authorized
  Response workflow of the existing MON backend.

Recorded source addresses remain explicit IPs. A source address is not proof
of which physical computer generated a packet. We do not label sources as PC-6
or PC-7 just because that is the test setup.

## Installation: PC-2 only

On the MON gateway computer, log in as `pc-2` and run:

```bash
cd ~/mon-three-code
git fetch --no-tags https://github.com/Saitanveesh/1.git \
  refs/heads/feature/mon-final-console-20261023
git show FETCH_HEAD:tools/mon-final-console-pc2.sh \
  > /tmp/mon-final-console-pc2.sh

# Read-only health, staged production build and all frontend tests:
bash /tmp/mon-final-console-pc2.sh --check

# Apply frontend files only. Takes backup and auto-rolls back on failure:
bash /tmp/mon-final-console-pc2.sh --apply
```

Both modes check the existing `mon-three-console-v2.service` and
`http://127.0.0.1:5174/` before installing anything. The installer stages
the exact GitHub revision, builds the console, and runs the test suite before
it writes to the running frontend. It backs up the existing `console-v2`
tree (except reusable `node_modules`) inside a private
`~/mon-three/mon-final-rollback.*` folder.

It updates **only** `~/mon-three/console-v2/` and restarts
`mon-three-console-v2.service`. No WireGuard service is restarted.

Once the output reports success, open:

`http://100.75.116.62:5174/?tenant=mon-lab&site=site-a`

Do a hard refresh in the browser to replace the cached frontend.

## Acceptance test with the real lab

Before the test, confirm on PC-5:

```bash
curl -fsS http://10.77.0.50:8085/health
```

The real Batch 1 training app V2 includes `"version":2`.

On PC-2, optionally inspect real HTTP headers as they pass the configured
tunnel interface:

```bash
sudo tcpdump -ni wg0 'host 10.77.0.50 and tcp port 8085'
```

Open the new MON dashboard and log in. From PC-7, run a **single**
lab-only training request:

```bash
curl --max-time 6 --path-as-is \
  'http://10.77.0.50:8085/download?file=../training-private/lab-only.txt'
```

Observe the actual response. If Suricata is running with the lab signature
and the packet takes the monitored path, a new matching EVE record can
appear and the MON alert notification can open. It should identify the
**observed source address**, not a hard-coded attacker computer.

Accept the release only after these checks:

- **Investigate** opens the specific alert with the correct address pair,
  rule, and time. No unrelated recorded incident appears instead.
- **Captured evidence** displays the exact EVE signature if still retained
  and zero or more genuinely observed header rows; missing headers are
  explicitly reported as unavailable, never filled with estimates.
- **Acknowledge** saves the exact new Suricata signature, displays the review
  timestamp, and stays acknowledged if you return from Alerts to the report.
- **Alerts** search, filter and sort work, and there are no fabricated rows.
- **Cases** opens real case records, their timelines and policy-gated response
  controls without executing automatic containment.
- Returning to **Dashboard** shows real capture measurements or an honest
  unavailable state. There are no synthetic packet-rate gauges.
- The existing PC-6, PC-7 and PC-5 WireGuard sessions continue working.

## Operational limits

The sensor's EVE log and IP-header event buffers have finite retention. A
historical alert can outlive the independent packet-header samples; absence
of a recent sample is not proof that the original signature did not occur.
AF_PACKET may observe forwarded IP frames twice, on ingress and egress.
A signature is evidence of a matched pattern, not proof of compromise.
Acknowledging an alert is distinct from formally closing a MON incident or
blocking a source. No browser component silently performs those actions.

This work is complete in version control and automated tests. Actual PC-2
deployment and live end-to-end acceptance require the commands above on the
real lab.
