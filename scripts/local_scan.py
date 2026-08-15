#!/usr/bin/env python3
"""Local authorized vulnerability scan orchestrator.

This script runs available local security tools and writes a normalized
findings file. It is intentionally read-only: it does not fix code, alter
dependencies, or perform dynamic attacks.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    "bower_components",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "target",
    "coverage",
    ".next",
    ".nuxt",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
}

MAX_CONTEXT_CHARS = 120_000
MAX_FILE_BYTES_DEFAULT = 1_000_000

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS Secret Key", re.compile(r"(?i)aws.{0,30}(?:secret|access).{0,30}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Stripe Secret", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic Password", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

MANIFEST_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "packages.lock.json",
    "*.csproj",
    "*.sln",
}


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def truncate_text(text: str, limit: int = MAX_CONTEXT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...truncated..."


def run_command(command, cwd=None, timeout=300):
    if not command or not tool_exists(command[0]):
        return {
            "available": False,
            "command": [str(part) for part in command],
            "install_hint": f"Install the '{command[0]}' CLI or rerun with a different scanner.",
        }

    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return {
            "available": True,
            "command": [str(part) for part in command],
            "returncode": completed.returncode,
            "stdout": truncate_text(completed.stdout or ""),
            "stderr": truncate_text(completed.stderr or ""),
        }
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "command": [str(part) for part in command],
            "returncode": None,
            "stdout": "",
            "stderr": f"Timed out after {timeout}s",
        }
    except OSError as exc:
        return {
            "available": True,
            "command": [str(part) for part in command],
            "returncode": None,
            "stdout": "",
            "stderr": f"OSError: {exc}",
        }


def normalize_scopes(scope_values):
    scopes = []
    seen = set()
    for value in scope_values:
        path = Path(value).expanduser().resolve()
        key = os.path.normcase(str(path))
        if key not in seen:
            seen.add(key)
            scopes.append(path)
    return scopes


def iter_files(scopes, max_file_bytes=MAX_FILE_BYTES_DEFAULT):
    for scope in scopes:
        if not scope.exists():
            continue
        if scope.is_file():
            yield scope
            continue
        for root, dirs, files in os.walk(scope):
            dirs[:] = [name for name in dirs if name not in EXCLUDED_DIRS]
            for name in files:
                file_path = Path(root) / name
                try:
                    if file_path.stat().st_size <= max_file_bytes:
                        yield file_path
                except OSError:
                    continue


def mask_secret(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-4:]


def run_fallback_secret_scan(scopes, max_file_bytes):
    findings = []
    files_scanned = 0
    for file_path in iter_files(scopes, max_file_bytes):
        files_scanned += 1
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for line_number, line in enumerate(text.splitlines(), start=1):
            for label, pattern in SECRET_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                secret = match.group(0)
                masked = mask_secret(secret)
                snippet = line[: match.start()] + masked + line[match.end() :]
                findings.append(
                    {
                        "tool": "builtin-regex",
                        "type": label,
                        "file": str(file_path),
                        "line": line_number,
                        "snippet": snippet.strip()[:240],
                    }
                )
                break

    return {
        "available": True,
        "tool": "builtin-regex",
        "command": ["builtin-regex"],
        "returncode": 0,
        "files_scanned": files_scanned,
        "findings": findings,
        "note": "Fallback secret scan used. Install Gitleaks or TruffleHog for stronger detection.",
    }


def run_secret_scan(scopes, output_dir, timeout, max_file_bytes):
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    if tool_exists("gitleaks"):
        results = []
        for index, scope in enumerate(scopes):
            report_path = raw_dir / f"gitleaks-{index}.json"
            command = [
                "gitleaks",
                "detect",
                "--source",
                str(scope),
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--no-banner",
            ]
            result = run_command(command, timeout=timeout)
            if report_path.exists():
                try:
                    result["stdout"] = truncate_text(report_path.read_text(encoding="utf-8", errors="ignore"))
                except OSError:
                    pass
            results.append(result)
        return {
            "tool": "gitleaks",
            "available": True,
            "results": results,
            "note": "Review raw/gitleaks-*.json for complete scanner output.",
        }

    if tool_exists("trufflehog"):
        results = []
        for index, scope in enumerate(scopes):
            command = [
                "trufflehog",
                "filesystem",
                "--json",
                "--no-update",
                str(scope),
            ]
            result = run_command(command, timeout=timeout)
            raw_path = raw_dir / f"trufflehog-{index}.jsonl"
            if result.get("stdout"):
                raw_path.write_text(result["stdout"], encoding="utf-8")
            results.append(result)
        return {
            "tool": "trufflehog",
            "available": True,
            "results": results,
            "note": "Review raw/trufflehog-*.jsonl for complete scanner output.",
        }

    if tool_exists("detect-secrets"):
        results = []
        for scope in scopes:
            command = ["detect-secrets", "scan", str(scope)]
            results.append(run_command(command, timeout=timeout))
        return {
            "tool": "detect-secrets",
            "available": True,
            "results": results,
        }

    return run_fallback_secret_scan(scopes, max_file_bytes)


def run_sast(scopes, output_dir, timeout, semgrep_config):
    if not tool_exists("semgrep"):
        return {
            "tool": "semgrep",
            "available": False,
            "install_hint": "Install Semgrep and rerun: pip install semgrep",
        }

    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    output_path = raw_dir / "semgrep.json"
    command = [
        "semgrep",
        "scan",
        "--config",
        semgrep_config,
        "--metrics=off",
        "--disable-version-check",
        "--json",
        "--output",
        str(output_path),
    ]
    command.extend(str(scope) for scope in scopes)
    result = run_command(command, timeout=timeout)

    if output_path.exists():
        try:
            result["stdout"] = truncate_text(output_path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            pass

    result["tool"] = "semgrep"
    result["note"] = "Review raw/semgrep.json for complete scanner output."
    return result


def collect_manifests(scopes):
    manifests = []
    for file_path in iter_files(scopes):
        if file_path.name in MANIFEST_NAMES:
            manifests.append(file_path)
    return manifests


def run_dependency_scan(scopes, output_dir, timeout):
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    manifests = collect_manifests(scopes)
    results = []
    available_tools = []

    if not manifests:
        return {
            "tool": "dependency-audit",
            "available": True,
            "results": [],
            "note": "No common dependency manifests found in scope.",
        }

    if tool_exists("osv-scanner"):
        available_tools.append("osv-scanner")
        output_path = raw_dir / "osv-scanner.json"
        command = [
            "osv-scanner",
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
        command.extend(str(path) for path in manifests)
        result = run_command(command, timeout=timeout)
        if output_path.exists():
            try:
                result["stdout"] = truncate_text(output_path.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                pass
        results.append(result)

    python_manifests = [
        path
        for path in manifests
        if path.name in {"requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock"}
    ]
    if python_manifests and tool_exists("pip-audit"):
        available_tools.append("pip-audit")
        output_path = raw_dir / "pip-audit.json"
        command = ["pip-audit", "--format=json", "--output", str(output_path)]
        if any(path.name == "requirements.txt" for path in python_manifests):
            command.extend(["--requirement", str(next(path for path in python_manifests if path.name == "requirements.txt"))])
        result = run_command(command, timeout=timeout)
        if output_path.exists():
            try:
                result["stdout"] = truncate_text(output_path.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                pass
        results.append(result)

    node_manifests = [
        path
        for path in manifests
        if path.name in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
    ]
    if node_manifests and tool_exists("npm"):
        available_tools.append("npm-audit")
        roots = sorted({str(path.parent) for path in node_manifests})
        for root in roots:
            results.append(
                run_command(
                    ["npm", "audit", "--json", "--prefix", root],
                    timeout=timeout,
                )
            )

    rust_manifests = [path for path in manifests if path.name == "Cargo.lock"]
    if rust_manifests and tool_exists("cargo"):
        available_tools.append("cargo-audit")
        for path in rust_manifests:
            results.append(
                run_command(
                    ["cargo", "audit", "--file", str(path), "--json"],
                    cwd=path.parent,
                    timeout=timeout,
                )
            )

    ruby_manifests = [path for path in manifests if path.name == "Gemfile.lock"]
    if ruby_manifests and tool_exists("bundle"):
        available_tools.append("bundle-audit")
        for path in ruby_manifests:
            results.append(
                run_command(
                    ["bundle", "audit", "check", "--update"],
                    cwd=path.parent,
                    timeout=timeout,
                )
            )

    return {
        "tool": "dependency-audit",
        "available": bool(available_tools),
        "available_tools": available_tools,
        "manifests": [str(path) for path in manifests],
        "results": results,
        "note": "Dependency tools may need network access to fetch vulnerability databases.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", action="append", required=True, help="File or directory to scan; repeat for multiple targets")
    parser.add_argument("--output-dir", default=".vuln-hunter", help="Directory for findings and raw output")
    parser.add_argument("--semgrep-config", default="auto", help="Semgrep config name or local rules path")
    parser.add_argument("--timeout", type=int, default=300, help="Per-command timeout in seconds")
    parser.add_argument("--max-file-size", type=int, default=MAX_FILE_BYTES_DEFAULT, help="Max file size for fallback scan")
    parser.add_argument("--no-secrets", action="store_true", help="Skip secret scanning")
    parser.add_argument("--no-sast", action="store_true", help="Skip Semgrep scanning")
    parser.add_argument("--no-deps", action="store_true", help="Skip dependency scanning")
    parser.add_argument("--json", action="store_true", help="Print findings JSON to stdout")
    args = parser.parse_args(argv)

    scopes = normalize_scopes(args.scope)
    missing = [str(path) for path in scopes if not path.exists()]
    output_dir = Path(args.output_dir).expanduser().resolve()
    raw_dir = output_dir / "raw"
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "skill": "local-vuln-hunter",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": [str(path) for path in scopes],
        "missing_scope": missing,
        "results": [],
    }

    if not args.no_secrets:
        report["results"].append(
            {
                "category": "secrets",
                "result": run_secret_scan(scopes, output_dir, args.timeout, args.max_file_size),
            }
        )

    if not args.no_sast:
        report["results"].append(
            {
                "category": "sast",
                "result": run_sast(scopes, output_dir, args.timeout, args.semgrep_config),
            }
        )

    if not args.no_deps:
        report["results"].append(
            {
                "category": "dependencies",
                "result": run_dependency_scan(scopes, output_dir, args.timeout),
            }
        )

    findings_path = output_dir / "findings.json"
    findings_path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=True))

    print(f"Wrote {findings_path}", file=sys.stderr)
    if missing:
        print(f"Missing scope paths: {', '.join(missing)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
