# Authorization And Scope

## Required Confirmation

Before starting, confirm that the user can answer all of these:

1. What is the exact target: repository path, directory, container, host, port, or URL?
2. Who owns the target?
3. What written authorization applies to this test?
4. Which activities are allowed: static review, dependency audit, secret detection, dynamic scanning, fuzzing?
5. Which activities are forbidden?
6. What is the stop condition or emergency contact?

## Scope Template

```text
Target: [path, repository, or service]
Owner: [name or team]
Authorization: [ticket, policy, contract, or written permission]
Start time: [timestamp]
Allowed:
- Read-only source and dependency review
- Secret scanning in the target path
- Dynamic requests against localhost endpoints
Forbidden:
- Real exploitation
- Credential theft or exfiltration
- Destructive or availability-impacting actions
- Third-party systems outside this scope
```

## Boundaries

Treat these as out of scope unless explicitly named:

- Cloud tenants or third-party infrastructure
- Production systems not owned by the user
- Systems accessed through credentials found during scanning
- Social engineering, credential stuffing, and denial of service

If a scanner discovers credentials for an out-of-scope system, stop using them and report the location without authenticating.

## Emergency Stop

If a command appears destructive, produces a shell, exfiltrates data, or exceeds scope, stop immediately and describe what happened before continuing.
