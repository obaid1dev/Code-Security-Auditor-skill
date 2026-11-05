# Severity and triage

Goal: a short list the developer trusts. Every reported item must survive these checks.

## Triage procedure (do for each scanner candidate)
1. **Read the code** around the line (whole function, plus callers if input source is unclear).
2. **Source**: can an untrusted party control the value? (request data, headers, uploaded files, webhook payloads, DB values originally from users, URLs, deep links, LLM output, third-party API responses.)
3. **Sink**: does it really reach a dangerous operation without effective neutralization (parameterization, escaping, allowlist, schema validation, framework default)?
4. **Barriers**: auth middleware, validators, WAF-free assumptions, feature flags, dead code, test-only code. Dead/unreachable code: mark Low or False positive with a note.
5. **Decide**: Confirmed, Needs verification (say exactly what would confirm it), or False positive (say why in `notes`).
6. Then look for what the scanner cannot see: missing auth on routes, missing ownership checks, missing RLS/rules, business-logic flaws, absent rate limiting. Use the entry-point list as your checklist: open each handler.

## Severity (impact x exploitability)
| Severity | Definition | Examples |
|---|---|---|
| Critical | Unauthenticated or trivially exploitable; full data breach, account/server takeover, or direct money loss | Live secret in repo/client bundle, unauthenticated SQLi/RCE, open DB rules/RLS off on user data, JWT signature not verified, auth bypass |
| High | Needs a normal account or modest effort; exposes other users' data, privilege escalation, stored XSS, SSRF to internal network | IDOR on private records, mass-assignment to admin, stored XSS, path traversal, weak password hashing with a leak path |
| Medium | Needs specific conditions or user interaction, or limited impact | Reflected XSS, CSRF on non-critical action, permissive CORS without credentials, verbose errors, missing rate limit on login |
| Low | Hardening/defense in depth, little direct exploit path | Missing headers, unpinned images, token in localStorage, test keys |
| Info | Observation, no action required | Public-by-design key, noted for completeness |

Adjust one level **up** when: internet-facing, handles payments/PII/health data, no auth required, easy automation. Adjust one level **down** when: needs admin already, internal-only, behind strong compensating control, test/dev-only code.

## Confidence
- high: pattern is unambiguous (live key format, `verify=False`, `eval(request...)`)
- medium: dangerous construct present; input source plausible but not proven
- low: heuristic hint (IDOR, mass assignment, SSRF); only report after reading the handler

## Status values
`Fixed` (patched and re-checked) · `Needs verification` (cannot confirm statically) · `Needs decision` (fix changes behavior/contract, or needs a product choice) · `Accepted risk` (user chose to keep) · `False positive` (omit from the report body) · `Candidate` (unreviewed; never ship in the report).

## Common false positives
- Placeholder or example values, env var names, test fixtures, docs.
- `exec`/`eval` in regex `.exec()`, DB `cursor.execute` with bound params, `child_process.exec` with a constant string.
- `md5`/`sha1` used for cache keys, ETags, file checksums (note it, don't escalate).
- `innerHTML = ""` or constant markup; `dangerouslySetInnerHTML` on sanitized or developer-authored HTML.
- Public-by-design keys: Firebase web config, Supabase anon (verify the JWT `role`), Stripe `pk_`, Google Maps browser keys (should still be restricted).
- `Math.random()` for UI jitter/IDs that are not security values.
