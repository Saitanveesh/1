# SERRATE — name and presentation

**Project:** SERRATE  
**Description:** Network Security & Adversary Simulation Lab  
**Implementation name:** MON Security Fabric  
**Maintainer:** [Sai Tanveesh](https://github.com/Saitanveesh)

SERRATE is the public name of a security engineering project used in controlled red/blue lab work. MON remains the implementation identifier.

## Documentation style

Use direct technical descriptions. Distinguish implemented code, CI-tested behavior, lab observations, planned integrations, and synthetic examples. Do not represent a diagram, a synthetic scenario, or an unmerged branch as proof of production functionality.

The README is intentionally text-first and uses one Mermaid workflow. Detailed architecture and safety diagrams belong in [technical workflows](WORKFLOWS.md). The retained `docs/brand/system-boundaries.svg` is a source-controlled topology diagram; do not replace it with generated portraits, fictitious dashboards, or simulated metrics presented as live evidence.

## Compatibility

Do not rename `mon` Python packages, `MON_*` variables, CLI commands, database objects, established APIs, deployed service names, or historical lab records as part of a documentation change. Any operational rename needs a separate migration and rollback plan.

The current repository is [Saitanveesh/SERRATE](https://github.com/Saitanveesh/SERRATE). Older source and deployment references to `Saitanveesh/1` may exist in historical or operational files and should only be updated after dependency review.

## Project claims

Describe verified behavior with the test environment and commit SHA. Do not describe SERRATE as production-certified, a complete automated exploitation system, or validated for every host or network. See [readiness](production-readiness.md) and [licensing](LICENSING.md).
