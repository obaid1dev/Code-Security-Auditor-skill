# Security Audit: demo-app (sample output)
_Generated 2026-11-05 | static review of the demo project | 9 files scanned_

## 1. Executive summary

| Severity | Count |
|---|---|
| CRITICAL | 4 |
| HIGH | 12 |
| MEDIUM | 13 |
| LOW | 4 |

Status: 29 needs verification, 4 fixed.

**Fix first:** AI/Google-style API key in `.env:1` (CRITICAL). API key in source. (AIza keys used for Firebase web config are public but must be restricted.)

## 2. Findings

| ID | Vulnerability | File | Line | Severity | CWE | Status |
|---|---|---|---|---|---|---|
| F-001 | AI/Google-style API key | `.env` | 1 | CRITICAL | CWE-798 | Needs verification |
| F-002 | Open database rules | `firestore.rules` | 1 | CRITICAL | CWE-284 | Needs verification |
| F-003 | Stripe live secret key | `src/app.py` | 6 | CRITICAL | CWE-798 | Fixed |
| F-004 | JWT accepted without verification | `src/app.py` | 45 | CRITICAL | CWE-347 | Fixed |
| F-005 | .env present and not gitignored | `.env` | 1 | HIGH | CWE-538 | Needs verification |
| F-006 | Hardcoded app/JWT/session secret | `src/app.py` | 7 | HIGH | CWE-798 | Needs verification |
| F-007 | Database URL with embedded credentials | `src/app.py` | 8 | HIGH | CWE-798 | Needs verification |
| F-008 | SQL injection (string-built query) | `src/app.py` | 16 | HIGH | CWE-89 | Fixed |
| F-009 | OS command injection | `src/app.py` | 21 | HIGH | CWE-78 | Fixed |
| F-010 | Server-side template injection | `src/app.py` | 25 | HIGH | CWE-1336 | Needs verification |
| F-011 | Path traversal | `src/app.py` | 29 | HIGH | CWE-22 | Needs verification |
| F-012 | Unsafe deserialization | `src/app.py` | 42 | HIGH | CWE-502 | Needs verification |
| F-013 | SQL injection (string-built query) | `src/server.js` | 5 | HIGH | CWE-89 | Needs verification |
| F-014 | OS command injection | `src/server.js` | 6 | HIGH | CWE-78 | Needs verification |
| F-015 | Server-side request forgery | `src/server.js` | 7 | HIGH | CWE-918 | Needs verification |
| F-016 | Secret exposed to client bundle via public env prefix | `src/server.js` | 11 | HIGH | CWE-200 | Needs verification |
| F-017 | Remote ADD / curl\|sh | `Dockerfile` | 2 | MEDIUM | CWE-494 | Needs verification |
| F-018 | Cleartext HTTP allowed (mobile) | `android/AndroidManifest.xml` | 1 | MEDIUM | CWE-319 | Needs verification |
| F-019 | Unsanitized HTML rendering | `src/App.jsx` | 2 | MEDIUM | CWE-79 | Needs verification |
| F-020 | Token in unencrypted mobile storage | `src/App.jsx` | 2 | MEDIUM | CWE-922 | Needs verification |
| F-021 | Debug mode enabled | `src/app.py` | 5 | MEDIUM | CWE-489 | Needs verification |
| F-022 | Open redirect | `src/app.py` | 33 | MEDIUM | CWE-601 | Needs verification |
| F-023 | Weak hash algorithm | `src/app.py` | 37 | MEDIUM | CWE-328 | Needs verification |
| F-024 | Sensitive data written to logs | `src/app.py` | 38 | MEDIUM | CWE-532 | Needs verification |
| F-025 | Overly permissive CORS | `src/server.js` | 2 | MEDIUM | CWE-942 | Needs verification |
| F-026 | Possible IDOR (lookup by request id) | `src/server.js` | 3 | MEDIUM | CWE-639 | Needs verification |
| F-027 | Mass assignment | `src/server.js` | 4 | MEDIUM | CWE-915 | Needs verification |
| F-028 | DOM XSS sink | `src/server.js` | 8 | MEDIUM | CWE-79 | Needs verification |
| F-029 | Insecure cookie/session settings | `src/server.js` | 10 | MEDIUM | CWE-614 | Needs verification |
| F-030 | No .gitignore | `.gitignore` | 0 | LOW | CWE-538 | Needs verification |
| F-031 | Container runs as root | `Dockerfile` | 1 | LOW | CWE-250 | Needs verification |
| F-032 | Unpinned base image | `Dockerfile` | 1 | LOW | CWE-1104 | Needs verification |
| F-033 | Auth token in web storage | `src/server.js` | 9 | LOW | CWE-922 | Needs verification |

## 3. Details and diffs

### F-001 · AI/Google-style API key · CRITICAL
**Where:** `.env:1`  |  **CWE-798**  |  **Confidence:** high

**Risk:** API key in source. (AIza keys used for Firebase web config are public but must be restricted.)

**Suggested fix:** Move to server-side env; apply key restrictions; rotate.

### F-002 · Open database rules · CRITICAL
**Where:** `firestore.rules:1`  |  **CWE-284**  |  **Confidence:** high

**Risk:** Anyone on the internet can read/write.

**Suggested fix:** Require auth and per-user ownership in rules.

### F-003 · Stripe live secret key · CRITICAL
**Where:** `src/app.py:6`  |  **CWE-798**  |  **Confidence:** high

**Risk:** Anyone with repo access can charge and refund through the live Stripe account. Key must also be rotated.

```diff
- STRIPE_KEY = "sk_l****"
+ STRIPE_KEY = os.environ["STRIPE_KEY"]
```

### F-004 · JWT accepted without verification · CRITICAL
**Where:** `src/app.py:45`  |  **CWE-347**  |  **Confidence:** high

**Risk:** Anyone can forge a token and log in as any user.

```diff
- jwt.decode(t, options={"verify_signature": False})
+ jwt.decode(t, os.environ["JWT_SECRET"], algorithms=["HS256"])
```

### F-005 · .env present and not gitignored · HIGH
**Where:** `.env:1`  |  **CWE-538**  |  **Confidence:** medium

**Risk:** Environment file may be committed. Check `git ls-files` and history.

**Suggested fix:** Add to .gitignore, untrack with git rm --cached, rotate every value inside.

### F-006 · Hardcoded app/JWT/session secret · HIGH
**Where:** `src/app.py:7`  |  **CWE-798**  |  **Confidence:** medium

**Risk:** Signing/session secret is a string literal in source (often short and guessable).

**Suggested fix:** Load a random >=32-byte secret from environment/secret manager and rotate the old one.

### F-007 · Database URL with embedded credentials · HIGH
**Where:** `src/app.py:8`  |  **CWE-798**  |  **Confidence:** medium

**Risk:** Connection string with password.

**Suggested fix:** Use env var and rotate the DB password.

### F-008 · SQL injection (string-built query) · HIGH
**Where:** `src/app.py:16`  |  **CWE-89**  |  **Confidence:** medium

**Risk:** Any visitor can read or alter the whole database by editing the id in the URL.

```diff
- cur.execute(f"SELECT * FROM users WHERE id = {uid}")
+ cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
```

### F-009 · OS command injection · HIGH
**Where:** `src/app.py:21`  |  **CWE-78**  |  **Confidence:** medium

**Risk:** A crafted host value runs arbitrary commands on the server.

```diff
- subprocess.run("ping -c 1 " + request.args["h"], shell=True)
+ subprocess.run(["ping", "-c", "1", request.args["h"]], check=True, timeout=5)
```

### F-010 · Server-side template injection · HIGH
**Where:** `src/app.py:25`  |  **CWE-1336**  |  **Confidence:** medium

**Risk:** Template source built from dynamic data.

**Suggested fix:** Pass user data as context variables, never as template source.

### F-011 · Path traversal · HIGH
**Where:** `src/app.py:29`  |  **CWE-22**  |  **Confidence:** low

**Risk:** File access path includes request data.

**Suggested fix:** basename() the name, resolve with realpath, verify it stays under the base dir, or use server-generated IDs.

### F-012 · Unsafe deserialization · HIGH
**Where:** `src/app.py:42`  |  **CWE-502**  |  **Confidence:** medium

**Risk:** Deserializing untrusted data can run code.

**Suggested fix:** Use JSON; yaml.safe_load; sign + verify payloads.

### F-013 · SQL injection (string-built query) · HIGH
**Where:** `src/server.js:5`  |  **CWE-89**  |  **Confidence:** medium

**Risk:** Query is built with template literal or concatenation.

**Suggested fix:** Use placeholders ($1 / ?) with a values array, or ORM query builders. Avoid *Unsafe raw APIs.

### F-014 · OS command injection · HIGH
**Where:** `src/server.js:6`  |  **CWE-78**  |  **Confidence:** medium

**Risk:** child_process exec with interpolated string.

**Suggested fix:** Use execFile/spawn with an args array; validate input.

### F-015 · Server-side request forgery · HIGH
**Where:** `src/server.js:7`  |  **CWE-918**  |  **Confidence:** low

**Risk:** Outbound request to a user-supplied URL.

**Suggested fix:** Allowlist hosts, block private/link-local ranges, disable redirects, resolve then check IP.

### F-016 · Secret exposed to client bundle via public env prefix · HIGH
**Where:** `src/server.js:11`  |  **CWE-200**  |  **Confidence:** high

**Risk:** Variables with these prefixes are shipped to browsers/apps; secrets placed there are public.

**Suggested fix:** Move to server-only env and call it from a backend route/edge function. Rotate the key.

### F-017 · Remote ADD / curl|sh · MEDIUM
**Where:** `Dockerfile:2`  |  **CWE-494**  |  **Confidence:** medium

**Risk:** Unverified remote code executed at build/run.

**Suggested fix:** Download, verify checksum/signature, then run.

### F-018 · Cleartext HTTP allowed (mobile) · MEDIUM
**Where:** `android/AndroidManifest.xml:1`  |  **CWE-319**  |  **Confidence:** high

**Risk:** App permits plaintext HTTP.

**Suggested fix:** Use HTTPS only; scope any exception to a specific dev domain.

### F-019 · Unsanitized HTML rendering · MEDIUM
**Where:** `src/App.jsx:2`  |  **CWE-79**  |  **Confidence:** medium

**Risk:** Raw HTML rendered by framework.

**Suggested fix:** Render as text; if HTML needed, sanitize with DOMPurify and an allowlist.

### F-020 · Token in unencrypted mobile storage · MEDIUM
**Where:** `src/App.jsx:2`  |  **CWE-922**  |  **Confidence:** medium

**Risk:** AsyncStorage is unencrypted plaintext on device.

**Suggested fix:** Use expo-secure-store / Keychain / Keystore.

### F-021 · Debug mode enabled · MEDIUM
**Where:** `src/app.py:5`  |  **CWE-489**  |  **Confidence:** medium

**Risk:** Debug mode exposes stack traces and sometimes an interactive console.

**Suggested fix:** Drive from env; force off in production.

### F-022 · Open redirect · MEDIUM
**Where:** `src/app.py:33`  |  **CWE-601**  |  **Confidence:** low

**Risk:** Redirect target is user-controlled.

**Suggested fix:** Allowlist destinations or require relative paths starting with a single '/'.

### F-023 · Weak hash algorithm · MEDIUM
**Where:** `src/app.py:37`  |  **CWE-328**  |  **Confidence:** medium

**Risk:** MD5/SHA-1 is unsafe for passwords, signatures or tokens.

**Suggested fix:** Passwords: Argon2id/bcrypt/scrypt. Integrity: SHA-256+. Non-security checksums can stay (document it).

### F-024 · Sensitive data written to logs · MEDIUM
**Where:** `src/app.py:38`  |  **CWE-532**  |  **Confidence:** low

**Risk:** Credential/PII or full request body may be logged.

**Suggested fix:** Log identifiers and outcomes only; redact secrets.

### F-025 · Overly permissive CORS · MEDIUM
**Where:** `src/server.js:2`  |  **CWE-942**  |  **Confidence:** medium

**Risk:** Any origin may call the API; dangerous with credentials.

**Suggested fix:** List explicit origins; never combine * with credentials.

### F-026 · Possible IDOR (lookup by request id) · MEDIUM
**Where:** `src/server.js:3`  |  **CWE-639**  |  **Confidence:** low

**Risk:** Record fetched by client-supplied id; verify an ownership/role check exists.

**Suggested fix:** Scope the query by owner (user_id = current user) or check policy before returning.

### F-027 · Mass assignment · MEDIUM
**Where:** `src/server.js:4`  |  **CWE-915**  |  **Confidence:** low

**Risk:** Request body passed straight into persistence; clients can set role/isAdmin/owner fields.

**Suggested fix:** Pick allowed fields explicitly or validate with a schema; never accept role/owner from the client.

### F-028 · DOM XSS sink · MEDIUM
**Where:** `src/server.js:8`  |  **CWE-79**  |  **Confidence:** medium

**Risk:** HTML sink; unsafe if value contains user data.

**Suggested fix:** Use textContent / framework escaping; sanitize with DOMPurify if HTML is required.

### F-029 · Insecure cookie/session settings · MEDIUM
**Where:** `src/server.js:10`  |  **CWE-614**  |  **Confidence:** medium

**Risk:** Cookie missing Secure/HttpOnly/SameSite protections.

**Suggested fix:** Set httpOnly, secure (in prod) and sameSite=lax/strict.

### F-030 · No .gitignore · LOW
**Where:** `.gitignore:0`  |  **CWE-538**  |  **Confidence:** high

**Risk:** Without .gitignore, .env files and build artifacts are easy to commit.

**Suggested fix:** Add .gitignore covering .env*, node_modules, build output, keys.

### F-031 · Container runs as root · LOW
**Where:** `Dockerfile:1`  |  **CWE-250**  |  **Confidence:** medium

**Risk:** No USER directive; process runs as root.

**Suggested fix:** Create an unprivileged user and add USER.

### F-032 · Unpinned base image · LOW
**Where:** `Dockerfile:1`  |  **CWE-1104**  |  **Confidence:** medium

**Risk:** Mutable base image tag.

**Suggested fix:** Pin a version or digest.

### F-033 · Auth token in web storage · LOW
**Where:** `src/server.js:9`  |  **CWE-922**  |  **Confidence:** medium

**Risk:** Tokens in web storage are readable by any XSS.

**Suggested fix:** Prefer HttpOnly+Secure+SameSite cookies.

## 4. Actions outside the code

- **Rotate every exposed credential** listed above. Removing it from source does not remove it from git history or from anyone who already cloned or built the app.
- If the repository was ever public or shared, treat the secret as compromised and check the provider's access logs.
- Purge history only after rotating (e.g., `git filter-repo` or BFG), then force-push and ask collaborators to re-clone.
- Run the ecosystem dependency audit (`npm audit`, `pip-audit`, `govulncheck`, `bundle audit`, `composer audit`) and review results; version-specific CVEs are not covered by this static pass.

## 5. Verification

Sample run on the intentionally vulnerable demo project; no test suite.

## 6. Prevention guidelines

- Ban string-built SQL: add a lint rule (e.g., Semgrep `sql-injection` ruleset) and review raw-query calls in PRs.
- Keep framework auto-escaping on; require a code-owner review for any `dangerouslySetInnerHTML`/`|safe`/`v-html`, and add a strict Content-Security-Policy.
- Treat shell and eval as banned APIs; wrap needed commands in one audited helper that takes an argv list.
- Install a secret scanner in pre-commit and CI (gitleaks or trufflehog) and enable GitHub secret scanning + push protection.
- Only prefix variables with NEXT_PUBLIC_/EXPO_PUBLIC_/VITE_ if they are safe to publish; keep real secrets behind a server route.
- Centralize authorization in one helper/middleware/policy layer and require an ownership check on every data fetch by id; add tests that user A cannot read user B's records.
- Validate request bodies with a schema (zod/joi/pydantic) and whitelist writable fields.

## Scope & limits

Static review of the files provided. It does not exercise the running app, infrastructure configuration, third-party services, or dependency CVEs, and cannot prove the absence of vulnerabilities.

_0 candidate(s) triaged as false positives and omitted; 0 candidate(s) not yet reviewed._
