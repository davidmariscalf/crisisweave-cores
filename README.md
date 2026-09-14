# crisisweave-cores

Public shared contract utilities for CrisisWeave.

This repository exists so the public stack has **no hidden dependency on `crisisweave-core`**, the older private repository. It contains only small, dependency-free rules that multiple public modules can agree on.

## Responsibilities

- shared contract version identifiers
- source/provenance checks
- GeoJSON Point validation
- stable JSON fingerprints
- public-feed privacy guardrails
- JSONL contract checking for CI and cross-repository integration

It does **not** own incident verification, alerting, worksite assignment, mapping, or authentication. Those responsibilities stay in their dedicated repositories.

## Public privacy boundary

The public contract rejects obvious direct-PII keys such as survivor names, phone numbers, emails, exact street addresses, date of birth and government IDs. This is a guardrail, not a complete privacy or data-protection system. Production deployments still require access control, data classification, retention rules, consent/legal basis, auditing, and organisation-specific governance.

## CLI

```bash
python contracts.py check --kind event verified.jsonl
python contracts.py check --kind worksite worksites.jsonl
```

## Test

```bash
python -m unittest discover -s tests -v
```

## Architecture

`crisisweave-cores` is deliberately tiny. Adding business logic here would recreate a monolith and make the repository split pointless.
