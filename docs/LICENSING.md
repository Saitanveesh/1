# Copyright, ownership and licensing policy

> **Current status (6 November 2026): no root open-source license has been issued for this repository.** This is an intentional status statement, not an MIT/Apache/GPL grant. Public visibility is not a grant to copy, modify, redistribute or commercially deploy the work beyond rights otherwise provided by law and GitHub's platform terms.

## Ownership and attribution

The SERRATE/MON repository is maintained as a personal engineering project under the GitHub account [Saitanveesh](https://github.com/Saitanveesh). Original source, documentation, architecture designs and original vector illustrations authored by the project maintainer are **copyrighted to their respective actual author(s)**; a repository owner is not automatically the author of every commit or third-party component.

**Copyright © 2026 Sai Tanveesh, to the extent of original works he authored and owns. All rights reserved unless and until expressly licensed.**

This notice does not imply ownership over upstream software, contributor work, third-party marks, publicly standardized formats or data. Examine commit authorship, source provenance, assignment/employment terms (if any), and embedded licenses before claiming exclusive ownership.

## External components and standards

MON references or integrates concepts/inputs from Zeek, Suricata, PostgreSQL, React, Python packages, STIX/TAXII, OpenC2, OCSF, MITRE ATT&CK, D3FEND and other projects/standards. Those names belong to their respective owners. Each component is independently licensed; the project owner's copyright notice **does not replace** upstream attribution and license obligations.

- Dependencies are specified in `pyproject.toml` and `console/package.json`; package versions and transitive licenses change.
- External command-line tools, kernels, operating systems, vendor adapters, trained content, rulesets, packet traces and imported threat intelligence can have their own terms.
- No third-party binary, dataset or logo is relicensed solely by appearing in a README.
- Before distributing installers, images, bundles or source copies, produce a machine-readable SBOM and verify all applicable notices, licenses, redistribution rights and compatibility.
- Keep third-party copyright headers and `NOTICE` files when applicable.
- Do not publish private PCAPs, IP/host inventories or live credentials to prove ownership or functionality.

## If the project is to become open source

**Option A — Apache-2.0:** Permissive, includes an express patent-license grant and preservation of notices. Often appropriate for a growing infrastructure project with third-party contributors.

**Option B — GPL-3.0:** Copyleft for distribution of derivatives, with obligations on redistributors. May limit integration into proprietary deployments.

**Option C — AGPL-3.0:** Copyleft with additional network-service source obligations. Relevant to SaaS, but imposes significant compliance expectations.

**Option D — MIT:** Minimal permissive terms; straightforward, but lacks the express Apache-style patent grant.

**Option E — Proprietary/source-visible:** Keep no OSI open-source license, or define a distinct source-available/commercial license after legal review. **Do not call that open source**.

A choice must be made by the relevant copyright holders; **this documentation update does not make that decision for them**. Once selected, add the exact root `LICENSE` file, reflect the SPDX identifier in package metadata, attribute third parties, and clarify contributor terms. Existing forks and previously granted rights (if any) do not automatically disappear when terms change.

## Why there is no made-up LICENSE file

Claiming an MIT or Apache license without validating ownership of all relevant material would be misleading. A standard license grants real rights, potentially irreversibly, and affects collaborators, patents and downstream distributors. Documentation here records the decision and checklist without pretending consent has been supplied.

## Contribution and permission requests

External contributors should discuss license and copyright terms with the maintainer before contributing substantial code. No blanket contributor license assignment (CLA) or DCO policy has been established; do not imply that pull requests transfer authorship automatically.

For a request to reuse code, seek a written permission or wait for an applicable published license. For alleged copyright or license violations, contact the maintainer privately with the file and supporting provenance.

## Trade names

“SERRATE” and “MON” are engineering/project identifiers. A GitHub or web search is **not** trademark clearance. Names of third-party tools and standards remain third-party marks.
