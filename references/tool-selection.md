# Tool Selection

Choose scanners by what is actually present in the target. Do not install or run remote upload tools.

## Source And Binary Analysis

| Stack or artifact | Preferred local tools |
| --- | --- |
| Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, C, C++ | Semgrep |
| High-value or complex codebases | CodeQL CLI |
| Compiled binaries or firmware | Ghidra, angr, checksec, binwalk |
| Terraform, Kubernetes, Dockerfile, CloudFormation | Semgrep, kube-linter, tfsec, checkov |

Semgrep command:

```powershell
semgrep scan --config auto --metrics=off --disable-version-check --json --output semgrep.json .
```

If a local rules directory is available, pass it as `--config path/to/rules`.

## Secrets

| Situation | Preferred local tools |
| --- | --- |
| Git history and working tree | Gitleaks |
| Filesystem and common credential patterns | TruffleHog |
| Python projects | detect-secrets |

Gitleaks command:

```powershell
gitleaks detect --source . --report-format json --report-path gitleaks.json --no-banner
```

## Dependencies

| Manifest | Preferred local tools |
| --- | --- |
| Multiple lockfiles or one-stop scan | OSV-Scanner |
| Python | pip-audit |
| Node.js | npm audit |
| Rust | cargo audit |
| Ruby | bundle-audit |
| .NET | dotnet list package --vulnerable --include-transitive |
| Go | govulncheck or OSV-Scanner |

Examples:

```powershell
osv-scanner --format json --output osv.json .
pip-audit --format=json --output pip-audit.json
npm audit --json
```

Do not treat `npm audit` or `pip-audit` output as proof until the vulnerable function is confirmed reachable in the runtime path.

## Dynamic Testing

Use only for local, authorized targets. Prefer non-destructive commands:

```powershell
nuclei -u http://127.0.0.1:8080 -severity critical,high,medium
ffuf -u http://127.0.0.1:8080/FUZZ -w wordlist.txt -mc 200,204,301,302,401,403
sqlmap -u "http://127.0.0.1:8080/?id=1" --batch --level=1 --risk=1
```

OWASP ZAP should use passive scanning first, then only explicitly approved active rules.

## Fuzzing

| Target | Preferred local tools |
| --- | --- |
| Python functions | Atheris |
| C/C++ | libFuzzer, AFL++ |
| HTTP inputs | ffuf |
| JavaScript/TypeScript | jsfuzz or quick unit-level fuzz harnesses |

Fuzzing is allowed only against isolated local builds. Limit runtime and do not mutate production data.
