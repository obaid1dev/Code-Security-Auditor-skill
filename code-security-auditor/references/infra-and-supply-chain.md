# Infrastructure, CI and supply chain

## Dependencies
- Read manifests and lockfiles; note framework versions. Recommend: `npm audit --omit=dev`, `pip-audit`, `govulncheck ./...`, `bundle audit`, `composer audit`, `cargo audit`, OSV-Scanner. If a package version matters to a claim, verify advisories with web search; never invent CVE ids or fixed versions from memory.
- Flag: unpinned `latest`/`*` ranges, git/URL dependencies, `postinstall` scripts from unknown packages, typo-squat-looking names, abandoned packages, packages with a lockfile missing.
- Commit lockfiles; use `npm ci`; enable Dependabot/Renovate; consider `--ignore-scripts` in CI.

## Docker
Non-root `USER`, pinned base image (tag + digest), multi-stage build so build tools/secrets do not ship, no secrets in `ENV`/`ARG`/layers (use BuildKit secrets), `.dockerignore` excludes `.env`, `.git`, `node_modules`; no `curl | sh`; read-only root fs and dropped capabilities in compose/k8s where possible; do not expose DB ports publicly (`ports: "5432:5432"` in compose binds all interfaces).

## CI/CD (GitHub Actions and similar)
- `pull_request_target` + checkout of PR head with secrets = takeover. Use `pull_request`, or separate untrusted build from privileged workflow.
- Never interpolate `${{ github.event.* }}` text (title, body, branch name) into `run:`; pass through `env:` and quote.
- Least-privilege `permissions:` block (`contents: read` default), pin third-party actions to a full commit SHA, protect `main`, require reviews.
- Secrets never echoed; mask derived values; avoid long-lived cloud keys (use OIDC).

## IaC / cloud
No `0.0.0.0/0` on SSH/DB ports, buckets private with Block Public Access, encryption at rest, IAM least privilege (no `"Action":"*"`/`"Resource":"*"` pairs), IMDSv2 enforced, no credentials in Terraform state/vars files committed, logging enabled.

## Git hygiene
`.gitignore` covers `.env*`, `*.pem`, `*.key`, `serviceAccount*.json`, `*.keystore`, `google-services.json` (if it holds restricted-only keys it may be fine; check), build output. Check history for secrets: `git log -p -S"<prefix>"`, gitleaks, trufflehog. Rotation first, history rewrite second.

## Security headers and transport
HTTPS everywhere + HSTS, redirect HTTP->HTTPS, TLS 1.2+, secure cookies, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `frame-ancestors`. Rate-limit auth, signup, password reset, OTP, and expensive endpoints; add request body/size limits and timeouts.
