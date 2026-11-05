# Code Security Auditor

[![CI](https://github.com/YOUR-USERNAME/code-security-auditor-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/code-security-auditor-skill/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An AI skill that works like a security engineer inside your workflow. It walks your whole codebase, finds vulnerabilities with the **exact file and line**, scores severity, applies **minimal, behavior-preserving patches**, verifies them, and hands you a clear **before/after audit report**.

Works with **Claude** (Claude.ai, Claude Code, Cowork) as a `.skill`, and the bundled scanner also runs standalone from any terminal.

> Static review only. It finds many real problems fast, but it cannot prove an app is secure. See [Limitations](#limitations).

---

## What it does

| Phase | What happens |
|---|---|
| 1. Map | Scans source, config, `.env` files, manifests, Docker, CI, mobile and DB rules. Lists every entry point where untrusted input arrives. |
| 2. Detect | Checks against OWASP Top 10 style risks: injection, secrets, auth, authorization, data exposure, crypto, config, supply chain. |
| 3. Locate and score | Every finding gets `file:line`, CWE, severity (Critical/High/Medium/Low), confidence and a plain-English impact. Candidates are verified by reading the code, not just by pattern match. |
| 4. Patch | Applies the smallest secure fix in your stack's idiom (parameterized queries, argv lists, env secrets, ownership checks, schema validation). Breaking changes are proposed, never applied silently. |
| 5. Verify | Re-scans, syntax-checks, runs your existing tests/linter/build when possible. |
| 6. Report | `SECURITY_AUDIT.md` with summary, findings table, diffs, actions outside the code, and prevention guidance. Optional SARIF for GitHub code scanning. |

### What it catches

- **Secrets**: AWS, GitHub, Stripe, OpenAI/Anthropic/Google-style keys, private keys, DB URLs with passwords, hardcoded JWT/session secrets, `.env` not gitignored, secrets exposed through `NEXT_PUBLIC_*` / `EXPO_PUBLIC_*` / `VITE_*`, Supabase `service_role` in client code.
- **Injection**: SQL, NoSQL, OS command, `eval`/`exec`, XSS (DOM, React, templates), SSTI, XXE, unsafe deserialization.
- **Access control**: IDOR hints, mass assignment, auth bypass flags, plus a checklist for the missing-control bugs scanners cannot see (no ownership check, no RLS, client-side entitlement checks, unsigned webhooks).
- **Auth and crypto**: MD5/SHA-1, fast password hashes, ECB/legacy ciphers, weak randomness, unverified or weakly signed JWTs, disabled TLS verification, insecure cookies, CSRF disabled.
- **Exposure**: wildcard CORS, debug mode, sensitive data in logs, token in `localStorage` / `AsyncStorage`, cleartext HTTP on mobile.
- **Server-side request flaws**: SSRF, open redirect, path traversal, risky file uploads.
- **Infra**: Docker (root user, unpinned image, `curl | sh`), GitHub Actions injection, Terraform public exposure, open Firebase rules, Supabase RLS gaps.
- **Stacks covered**: Next.js, React, Vue, Expo/React Native, Express, Flask, FastAPI, Django, Rails, Laravel, Spring, Go, Supabase, Firebase, serverless.

See a real example of the output: [`examples/sample-report.md`](examples/sample-report.md).

---

## Install

### Claude.ai (web, desktop, mobile)
1. Download `code-security-auditor.skill` from the [latest release](../../releases/latest) (or zip the `code-security-auditor/` folder yourself).
2. Open **Settings -> Capabilities -> Skills**, upload the file, and enable it.

### Claude Code
```bash
git clone https://github.com/obaid1dev/Code-Security-Auditor-skill.git
cp -r code-security-auditor-skill/code-security-auditor ~/.claude/skills/        # all projects
# or, for a single project:
cp -r code-security-auditor-skill/code-security-auditor .claude/skills/
```

### Build the `.skill` file yourself
```bash
zip -r code-security-auditor.skill code-security-auditor -x "*/__pycache__/*"
```

---

## Use it

Just ask. The skill triggers on security-related requests, even when you do not say "security".

```
Audit this repo and fix what you find.
Is this safe to deploy? Check before I launch.
Review this PR diff for vulnerabilities, report only, don't edit.
Scan my Expo app for leaked keys before I submit to the Play Store.
Check my Supabase setup for missing RLS.
Quick triage: anything critical in this folder?
```

| Mode | Trigger phrases | Result |
|---|---|---|
| Full audit + patch (default) | "audit and fix", "secure this" | Findings, applied patches, report |
| Audit only | "just report", "don't change anything" | Findings and proposed diffs |
| PR / diff review | "review this PR/diff" | Changed code and its callers |
| Snippet review | paste a function | Inline findings and a patched snippet |
| Quick triage | "anything scary?" | Critical/High only |

---

## Use the scanner on its own

The pre-scanner has **no dependencies** (Python 3.9+). It is a candidate finder; confirm findings before acting.

```bash
python code-security-auditor/scripts/scan.py ./my-project --out findings.json
python code-security-auditor/scripts/scan.py ./my-project --min-severity medium --include-tests
```

Example output:
```
Scanned 9 files | manifests: 4 | entry points: 12
Candidates: critical=4, high=12, medium=13, low=4
  F-001 [CRITICAL/high  ] .env:1  AI/Google-style API key (CWE-798)
  F-007 [HIGH    /medium] src/app.py:17  SQL injection (string-built query) (CWE-89)
  ...
```

Turn triaged findings into a report:
```bash
python code-security-auditor/scripts/report.py findings.json --out SECURITY_AUDIT.md --sarif audit.sarif
```

Edit `status` in `findings.json` (`Fixed`, `Needs verification`, `Needs decision`, `False positive`, `Accepted risk`) before generating. Findings still marked `Candidate` are left out of the report.

Silence a reviewed line by adding a comment containing `audit-ignore`.

Secret values are always masked in scanner and report output.

---

## Repository layout

```
code-security-auditor/
  SKILL.md                        workflow, modes, patching rules
  scripts/scan.py                 deterministic pre-scanner (~70 rules)
  scripts/report.py               markdown + SARIF report generator
  references/patterns.md          15 vulnerability classes with fixes
  references/frameworks.md        stack-specific checklists
  references/severity-and-triage.md
  references/infra-and-supply-chain.md
examples/sample-report.md         sample output on the demo project
tests/                            unit tests (demo project built at runtime)
.github/workflows/ci.yml          tests and SKILL.md validation
```

## Design principles

- **Signal over volume.** Candidates are triaged by reading code; false positives are dropped, not reported.
- **Minimal patches.** No reformatting, renames, or refactors. Behavior-changing fixes need your approval.
- **Never leak secrets.** Masked everywhere. Always tells you to rotate; removing a key from code does not remove it from git history.
- **Honest limits.** Says what it could not verify and what needs a human decision.
- **Static and safe.** Never runs your app, never touches live systems, never writes weaponized exploits.

## Limitations

- Static analysis: no runtime behavior, infrastructure state or third-party services.
- Pattern rules produce candidates; some will be false positives and some real bugs (especially logic and authorization flaws) need the model's code reading to find.
- Dependency CVEs are not checked offline. Run `npm audit`, `pip-audit`, `govulncheck`, `bundle audit` or OSV-Scanner alongside it.
- Not a replacement for a professional penetration test on high-risk systems.

## Development

```bash
python -m unittest discover -s tests -v
python tests/demo_project.py ./demo-vulnerable      # generate the intentionally vulnerable demo
python code-security-auditor/scripts/scan.py ./demo-vulnerable
```

See [CONTRIBUTING.md](CONTRIBUTING.md) to add rules or stack checklists.

## License

[MIT](LICENSE)
