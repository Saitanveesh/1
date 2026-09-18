# ADR 0013: Incident investigation and enforcement inventory

Status: Accepted

## Decision

MON exposes an incident investigation object that joins the incident with its exact
finding IDs, deduplicated evidence, affected assets, incident graph and topology-bound
enforcement capabilities.

The investigation layer does not rank containment actions and does not execute them.
It reports what controls are bound to an affected asset, their health, declared
capabilities, topology distance and connector/topology blast-radius estimate when one
has actually been supplied.

Policy evaluation and enforcement-point selection remain in the response-planning path.

## Console

The live snapshot now carries enforcement points and bindings, allowing the black/white
operator console to render the actual enforcement inventory without polling or
fabricated coverage metrics.

## Safety

If a topology connector has not supplied a blast-radius estimate, the investigation
shows that it is unknown. MON must not invent a single-host blast radius for a switch,
VLAN, firewall or other shared control surface.
