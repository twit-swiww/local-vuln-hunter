# Reporting

## Severity Definitions

| Severity | Meaning |
| --- | --- |
| Critical | Remote or local attacker can compromise the system, expose secrets, or execute arbitrary code without special conditions. |
| High | Attacker can access sensitive data, bypass important controls, or gain significant unauthorized capability. |
| Medium | Security control is weakened or limited data exposure is possible under realistic conditions. |
| Low | Hardening issue, missing defense-in-depth, or low-impact information disclosure. |
| Info | No direct weakness; useful context for the assessor. |

Use the same severity consistently. Do not inflate scanner CVSS scores without reachability evidence.

## Finding Status

- Confirmed: reachable and supported by evidence.
- Likely: strong indicators but incomplete evidence.
- False positive: scanner signal does not apply.
- Accepted risk: real but intentionally accepted by the owner.
- Needs more evidence: not enough context to decide.

## Evidence Requirements

A confirmed finding must include:

```text
Title:
Severity:
Status:
Location:
Affected component:
Reachability:
Impact:
Evidence:
Remediation:
References:
```

For dependency findings, include the vulnerable package, installed version, fixed version, call path, and whether the vulnerable function is reachable.

For secret findings, report the secret type and file/line but never the secret value.

## Proof Of Concept Rules

- Keep proof of concept minimal, local, and non-destructive.
- Use a controlled test account or isolated fixture.
- Label the artifact `PoC - evidence only`.
- Do not include working exploitation against out-of-scope targets.

## Report Template

```markdown
# Vulnerability Assessment

## Scope And Authorization
## Executive Summary
## Methodology
## Findings
### Finding 1
## False Positives And Accepted Risks
## Remediation Plan
## Re-Test Checklist
```
