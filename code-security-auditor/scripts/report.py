#!/usr/bin/env python3
"""
Build the final audit report from a triaged findings JSON.

The auditor edits findings.json after reading the code: set `status`
(Fixed | Needs verification | Needs decision | False positive | Accepted risk),
and optionally `before`, `after`, `impact`, `notes`, `verified`.

Usage:
  python report.py findings.json --out SECURITY_AUDIT.md [--sarif audit.sarif]
                   [--title "Security Audit: my-app"] [--tests "npm test: 42 passed"]
Candidates still marked `Candidate` are excluded from the report body and counted
separately so unreviewed noise never reaches the user.
"""
import argparse
import json
from collections import Counter
from datetime import date
from pathlib import Path

ORDER = ["critical", "high", "medium", "low", "info"]
REPORTED = {"Fixed", "Needs verification", "Needs decision", "Accepted risk", "Open"}
BADGE = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def esc(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def build(data, title, tests):
    fs = data["findings"]
    live = [f for f in fs if f.get("status") in REPORTED]
    fp = [f for f in fs if f.get("status") == "False positive"]
    unreviewed = [f for f in fs if f.get("status", "Candidate") == "Candidate"]
    live.sort(key=lambda f: (ORDER.index(f["severity"]), f["file"], f["line"]))
    by_sev = Counter(f["severity"] for f in live)
    by_status = Counter(f["status"] for f in live)
    L = []
    L.append(f"# {title}")
    L.append(f"_Generated {date.today().isoformat()} | static review of `{Path(data['root']).name}` | "
             f"{data['files_scanned']} files scanned_\n")
    L.append("## 1. Executive summary\n")
    if not live:
        L.append("No confirmed vulnerabilities were found in the reviewed scope. A static review cannot prove absence of flaws; see Scope & limits.\n")
    else:
        L.append("| Severity | Count |\n|---|---|")
        for s in ORDER:
            if by_sev.get(s):
                L.append(f"| {BADGE[s]} | {by_sev[s]} |")
        L.append("")
        L.append("Status: " + ", ".join(f"{v} {k.lower()}" for k, v in by_status.items()) + ".")
        top = live[0]
        L.append(f"\n**Fix first:** {top['name']} in `{top['file']}:{top['line']}` ({BADGE[top['severity']]}). "
                 f"{top.get('impact', top['message'])}\n")
    L.append("## 2. Findings\n")
    if live:
        L.append("| ID | Vulnerability | File | Line | Severity | CWE | Status |\n|---|---|---|---|---|---|---|")
        for f in live:
            L.append(f"| {f['id']} | {esc(f['name'])} | `{esc(f['file'])}` | {f['line']} | {BADGE[f['severity']]} | "
                     f"{f['cwe']} | {f['status']} |")
        L.append("")
    else:
        L.append("None.\n")
    L.append("## 3. Details and diffs\n")
    for f in live:
        L.append(f"### {f['id']} · {f['name']} · {BADGE[f['severity']]}")
        L.append(f"**Where:** `{f['file']}:{f['line']}`  |  **{f['cwe']}**  |  **Confidence:** {f.get('confidence', 'n/a')}\n")
        L.append(f"**Risk:** {f.get('impact', f['message'])}\n")
        if f.get("before") or f.get("after"):
            L.append("```diff")
            for ln in (f.get("before") or "").splitlines():
                L.append(f"- {ln}")
            for ln in (f.get("after") or "").splitlines():
                L.append(f"+ {ln}")
            L.append("```")
        else:
            L.append(f"**Suggested fix:** {f['fix']}")
        if f.get("notes"):
            L.append(f"\n**Notes:** {f['notes']}")
        L.append("")
    actions = [f for f in live if f["rule"].startswith(("SEC-", "HYG-ENV", "CLIENT-SECRET", "SUPABASE"))]
    L.append("## 4. Actions outside the code\n")
    if actions:
        L.append("- **Rotate every exposed credential** listed above. Removing it from source does not remove it from git history or from anyone who already cloned or built the app.")
        L.append("- If the repository was ever public or shared, treat the secret as compromised and check the provider's access logs.")
        L.append("- Purge history only after rotating (e.g., `git filter-repo` or BFG), then force-push and ask collaborators to re-clone.")
    L.append("- Run the ecosystem dependency audit (`npm audit`, `pip-audit`, `govulncheck`, `bundle audit`, `composer audit`) and review results; version-specific CVEs are not covered by this static pass.")
    L.append("")
    L.append("## 5. Verification\n")
    L.append(tests or "No automated tests, linter, or build were run (none found or not executed).")
    L.append("")
    L.append("## 6. Prevention guidelines\n")
    for g in prevention(live):
        L.append(f"- {g}")
    L.append("")
    L.append("## Scope & limits\n")
    L.append("Static review of the files provided. It does not exercise the running app, infrastructure configuration, "
             "third-party services, or dependency CVEs, and cannot prove the absence of vulnerabilities.")
    L.append(f"\n_{len(fp)} candidate(s) triaged as false positives and omitted; {len(unreviewed)} candidate(s) not yet reviewed._")
    return "\n".join(L) + "\n"


def prevention(live):
    rules = {f["rule"] for f in live}
    out = []
    if any(r.startswith("INJ-SQL") for r in rules):
        out.append("Ban string-built SQL: add a lint rule (e.g., Semgrep `sql-injection` ruleset) and review raw-query calls in PRs.")
    if any(r.startswith(("INJ-XSS", "INJ-SSTI")) for r in rules):
        out.append("Keep framework auto-escaping on; require a code-owner review for any `dangerouslySetInnerHTML`/`|safe`/`v-html`, and add a strict Content-Security-Policy.")
    if any(r.startswith("INJ-CMD") or r == "INJ-EVAL" for r in rules):
        out.append("Treat shell and eval as banned APIs; wrap needed commands in one audited helper that takes an argv list.")
    if any(r.startswith(("SEC-", "HYG-ENV", "CLIENT-SECRET")) for r in rules):
        out.append("Install a secret scanner in pre-commit and CI (gitleaks or trufflehog) and enable GitHub secret scanning + push protection.")
        out.append("Only prefix variables with NEXT_PUBLIC_/EXPO_PUBLIC_/VITE_ if they are safe to publish; keep real secrets behind a server route.")
    if rules & {"IDOR-HINT", "MASS-ASSIGN", "AUTH-DISABLED"}:
        out.append("Centralize authorization in one helper/middleware/policy layer and require an ownership check on every data fetch by id; add tests that user A cannot read user B's records.")
        out.append("Validate request bodies with a schema (zod/joi/pydantic) and whitelist writable fields.")
    if rules & {"JWT-NOVERIFY", "JWT-DECODE-ONLY", "JWT-WEAK-SECRET", "CRYPTO-WEAKHASH", "CRYPTO-PWD-FASTHASH"}:
        out.append("Standardize on Argon2id/bcrypt for passwords and verified, expiring JWTs with an explicit algorithm allowlist; keep crypto choices in one module.")
    if rules & {"CORS-WILDCARD", "COOKIE-FLAGS", "CSRF-OFF", "DEBUG-ON"}:
        out.append("Drive security-relevant config from environment with safe defaults and a startup check that fails if production runs with debug/CORS-any enabled.")
    if "LOG-SENSITIVE" in rules:
        out.append("Introduce a logging wrapper that redacts password/token/authorization fields automatically.")
    out.append("Run `scan.py` (or Semgrep/CodeQL) in CI on every pull request so regressions are caught before merge.")
    out.append("Keep dependencies current with Dependabot/Renovate and fail CI on high-severity advisories.")
    return out[:7]


def sarif(data):
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules, results = {}, []
    for f in data["findings"]:
        if f.get("status") not in REPORTED:
            continue
        rules.setdefault(f["rule"], {"id": f["rule"], "name": f["name"], "shortDescription": {"text": f["name"]},
                                     "properties": {"tags": [f["cwe"], "security"]}})
        results.append({"ruleId": f["rule"], "level": lvl[f["severity"]], "message": {"text": f["message"]},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                                            "region": {"startLine": max(1, f["line"])}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "code-security-auditor", "rules": list(rules.values())}},
                      "results": results}]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("--out", default="SECURITY_AUDIT.md")
    ap.add_argument("--sarif")
    ap.add_argument("--title", default="Security Audit Report")
    ap.add_argument("--tests", default="")
    a = ap.parse_args()
    data = json.loads(Path(a.findings).read_text())
    Path(a.out).write_text(build(data, a.title, a.tests))
    if a.sarif:
        Path(a.sarif).write_text(json.dumps(sarif(data), indent=2))
    print(f"Wrote {a.out}" + (f" and {a.sarif}" if a.sarif else ""))


if __name__ == "__main__":
    main()
