---
name: local-vuln-hunter
description: Authorized local vulnerability discovery and triage for source code, dependencies, secrets, and local services. Use when Codex should audit or hunt for security weaknesses in a codebase or local target that the user owns or has explicit written permission to test. Covers SAST, dependency and secret scanning, reachability analysis, evidence collection, severity triage, and remediation guidance. Do not use for unauthorized targets, real-world exploitation, credential exfiltration, or destructive testing.
---

# Local Vuln Hunter

## Overview

Run authorized, local-first vulnerability hunting. Use deterministic scanners for breadth and deterministic evidence collection, then apply AI reasoning for reachability, impact, false-positive triage, and remediation.

## Safety Rules

Before doing anything else:

1. Confirm the target is local, owned by the user, or covered by explicit written authorization.
2. Record the exact scope: files, directories, hosts, ports, URLs, and endpoints.
3. Refuse or stop if authorization is unclear, the target is third-party infrastructure, or the request is for weaponization, credential theft, or unauthorized access.
4. Keep everything non-destructive. Do not run exploit code, drop shells, alter data, lock accounts, or degrade services.
5. Do not exfiltrate source code, credentials, or findings outside the user-controlled environment.
6. Mask secrets in reports. Store raw scanner output only in the local output directory.
7. If a finding needs proof, collect a minimal, reversible, isolated proof of concept and clearly label it as evidence, not an exploit kit.

If the user only says "find vulnerabilities" without scope, ask for the target path and authorization before scanning.

## Workflow

### 1. Confirm Scope And Inventory

Run read-only discovery first:

```powershell
Get-ChildItem -Recurse -Force
```

Identify languages, frameworks, package manifests, lockfiles, entry points, configuration files, and local service ports. Prefer manifests and lockfiles as ground truth.

### 2. Run Local Scanners

Run the bundled orchestrator from the repository root:

```powershell
python scripts/local_scan.py --scope . --output-dir .vuln-hunter
```

The script runs available local tools and records results in `.vuln-hunter/findings.json` plus raw output under `.vuln-hunter/raw/`. It does not require any third-party tool; unavailable tools are reported as `not_installed` with an install hint.

Common options:

```powershell
python scripts/local_scan.py --scope . --output-dir .vuln-hunter --semgrep-config auto
python scripts/local_scan.py --scope src --scope config --no-secrets --json
```

Read `.vuln-hunter/findings.json` before drawing conclusions. Prefer installing and running the right scanner when the fallback was used.

### 3. Add Missing Scanner Coverage

Use [tool-selection.md](references/tool-selection.md) to choose the best local tools for the stack. Install them only with the user's permission. Never upload code to a remote scanner.

Typical additions:

- Semgrep or CodeQL for SAST
- Gitleaks, TruffleHog, or detect-secrets for secrets
- OSV-Scanner, pip-audit, npm audit, cargo audit, or bundle-audit for dependencies
- Nuclei, ffuf, OWASP ZAP, or sqlmap with non-destructive flags for authorized local dynamic testing

### 4. Verify And Triage

For each scanner finding:

- Check whether the vulnerable code or dependency is actually reachable from an entry point or exposed endpoint.
- Confirm the language, framework, and version match the finding.
- Check whether mitigations, sanitizers, authentication, or deployment controls make it unexploitable.
- Treat dependency findings as real only when the vulnerable function is imported or the package is included at runtime.
- Distinguish true positives, false positives, accepted risk, and missing evidence.

Do not report scanner output as fact. Validate at least the highest-severity findings manually.

### 5. Collect Evidence

For each confirmed finding, capture:

- File path and line range
- The exact code or dependency version
- The vulnerable input path or call chain
- The observed condition or a minimal, non-destructive reproduction
- Why the finding is reachable and what an attacker could do

Keep credentials and secrets masked.

### 6. Write The Report

Use [reporting.md](references/reporting.md) for severity definitions, evidence rules, and the report template. Include:

- Scope and authorization statement
- Executive summary
- Prioritized findings with evidence
- False positives and accepted risks
- Remediation recommendations
- Commands used and re-test steps

### 7. Propose Fixes And Re-Test

Recommend the smallest safe fix for each finding. When the user applies a fix, re-run only the relevant scanner and update the report instead of repeating the whole engagement.

## Dynamic Testing Guardrails

Only run dynamic testing when:

- The target is local or explicitly in scope
- The user authorized the exact request set
- Requests are non-destructive and rate-limited
- Authentication or test accounts are used where appropriate

Prefer safe flags such as Nuclei `-severity`, sqlmap `--batch --level=1 --risk=1`, and ZAP passive or safe active rules. Do not bypass WAFs, brute-force credentials, or chain a finding into real exploitation.

## Output Expectations

Prefer Markdown reports with stable file names in the user-specified output directory. Keep scanner JSON in `.vuln-hunter/` and do not commit it to the target repository unless the user asks.

## Resources

- `scripts/local_scan.py`: local scanner orchestrator and fallback secret scan
- `references/tool-selection.md`: scanner matrix and install commands
- `references/reporting.md`: severity, evidence, and report standards
- `references/authorization-scope.md`: authorization and scope interview template
