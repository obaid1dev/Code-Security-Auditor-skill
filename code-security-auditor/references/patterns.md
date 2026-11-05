# Vulnerability patterns and fixes

Read the section for each class the scanner flagged, plus any class relevant to the entry points you mapped. Every fix keeps the function's inputs and outputs unchanged.

## Contents
1. SQL injection (CWE-89)
2. Command injection (CWE-78) and eval (CWE-95)
3. XSS (CWE-79)
4. SSTI (CWE-1336)
5. NoSQL injection (CWE-943)
6. Authorization: IDOR, missing checks, mass assignment (CWE-639/862/915)
7. Authentication: passwords, JWT, sessions (CWE-256/347/384/916)
8. Secrets (CWE-798)
9. SSRF (CWE-918), open redirect (CWE-601)
10. Path traversal and uploads (CWE-22/434)
11. Deserialization and XXE (CWE-502/611)
12. CORS, CSRF, cookies, headers
13. Data exposure and logging (CWE-200/532)
14. Race conditions and business logic (CWE-362/840)
15. Prompt injection in LLM features (OWASP LLM01)

---

## 1. SQL injection
Taint trace: request value -> any variable -> string that reaches `execute/query/raw`.
```python
# Before
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
# After
cur.execute("SELECT * FROM users WHERE email = %s", (email,))   # sqlite3 uses ?
```
```js
// Before
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
// After
db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
// Prisma: replace $queryRawUnsafe(str) with $queryRaw`SELECT ... ${id}` (tagged template binds params)
```
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id"); $stmt->execute(['id' => $id]);
```
```go
db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)
```
Cannot be parameterized: table/column names, ORDER BY direction, LIMIT in some drivers. Map input to an allowlist: `col = {"name":"name","date":"created_at"}.get(sort, "created_at")`.
Also check: ORM `.extra()`, `.raw()`, `text()` with f-strings, `Sequelize.query` with replacements built by hand, stored procedures that concatenate inside.

## 2. Command injection and eval
```python
# Before
subprocess.run(f"convert {name} out.png", shell=True)
# After
subprocess.run(["convert", name, "out.png"], check=True, timeout=30)
# Arguments beginning with "-" can become flags: put "--" before user values when the tool supports it.
```
```js
// Before: exec(`ping -c 1 ${host}`)
// After
execFile("ping", ["-c", "1", host], { timeout: 5000 }, cb);
```
Validate in addition: `if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host): abort(400)`.
`eval`/`new Function`/`exec`: replace with `JSON.parse`, `ast.literal_eval`, or a dict of allowed operations.

## 3. XSS
Reflected, stored, DOM. Sinks: `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `|safe`, `mark_safe`, `Markup`, `<%-`, `{{{ }}}`, `document.write`, `href={userUrl}` (javascript: URLs), `eval`-like timers.
```jsx
// Before: <div dangerouslySetInnerHTML={{ __html: comment.body }} />
// After (text):      <div>{comment.body}</div>
// After (rich text): <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />
```
URLs: validate scheme `new URL(u).protocol in ["http:", "https:"]` before using in `href`/`src`.
Defense in depth: strict CSP (`default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'`), cookies `HttpOnly`.
Markdown renderers: disable raw HTML or sanitize output.

## 4. SSTI
```python
# Before: render_template_string("Hello " + name)
# After:  render_template_string("Hello {{ name }}", name=name)
```
User text must never be template source (Jinja2, Twig, ERB, EJS, Pug, Handlebars, Freemarker, Velocity).

## 5. NoSQL injection
```js
// Before: User.findOne({ email: req.body.email, password: req.body.password })   // body.password = {"$ne": null}
// After
const { email, password } = schema.parse(req.body);          // zod: z.string()
const user = await User.findOne({ email: String(email) });
if (!user || !(await bcrypt.compare(password, user.hash))) return res.status(401).end();
```
Also block `$where`, `$function`, and operator keys in user-supplied filters; `express-mongo-sanitize` is a stopgap, schema validation is the fix.

## 6. Authorization
The most common critical bug in real apps and the one scanners miss. For every route that takes an id or touches user data ask three questions: Who is the caller? May they perform this action? May they touch THIS record?
```python
# IDOR - Before: order = Order.query.get(order_id)
order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
```
```js
const doc = await Doc.findOne({ _id: req.params.id, owner: req.user.id });
if (!doc) return res.status(404).end();     // 404 avoids confirming existence
```
Function-level: admin routes need a server-side role check (`@require_role("admin")`, middleware); hiding a button is not a control.
Mass assignment: `User.create(req.body)` lets clients send `{"role":"admin"}`. Destructure allowed fields or validate with a schema that strips unknown keys. Never accept `role`, `isAdmin`, `ownerId`, `price`, `balance` from the client.
Multi-tenant: every query includes the tenant id from the session, not from the request.
Firebase/Supabase: authorization lives in rules/RLS (see frameworks.md); client checks are cosmetic.

## 7. Authentication
Passwords: Argon2id (`argon2-cffi`, `argon2` npm), bcrypt cost >= 12, or scrypt. Migration without lockout:
```python
if verify_new(hash, pw): ok
elif legacy_md5(pw) == hash: ok; user.hash = argon2.hash(pw); save()   # upgrade on successful login
```
Compare secrets with `hmac.compare_digest` / `crypto.timingSafeEqual`.
JWT:
```js
// Before: const p = jwt.decode(token)
const p = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"], issuer: "my-app", audience: "my-web" });
```
Issue with `expiresIn` (15 min access + rotating refresh). Reject `alg: none`. For RS256 pin the key, do not trust `jwk`/`jku` headers. Keep a revocation path (token version on user row).
Sessions: regenerate id on login, expire idle sessions, `HttpOnly; Secure; SameSite=Lax`.
Reset/OTP flows: random 128-bit tokens, single use, short expiry, rate-limited, identical responses for known/unknown emails. Rate-limit login (per account and per IP) and add lockout/backoff.

## 8. Secrets
Remove the literal, read from env, add to `.env.example` as a placeholder, ensure `.env*` is gitignored.
```python
STRIPE_KEY = os.environ["STRIPE_KEY"]          # fail fast if missing; do not default to a real value
```
```js
const key = process.env.STRIPE_KEY; if (!key) throw new Error("STRIPE_KEY missing");
```
Report names and masked prefixes only. ALWAYS tell the user to rotate: removing from HEAD does not remove from history, forks, CI logs, or built bundles. Client bundles (`NEXT_PUBLIC_*`, `EXPO_PUBLIC_*`, `VITE_*`) are public: a real secret there needs a server proxy route, not a rename.
Keys that are meant to be public (Firebase web config, Supabase anon, Stripe publishable `pk_`) are Low unless unrestricted; recommend key restrictions and RLS/rules.

## 9. SSRF and open redirect
```python
from urllib.parse import urlparse; import ipaddress, socket
def safe_url(u):
    p = urlparse(u)
    if p.scheme not in ("http", "https") or p.hostname not in ALLOWED_HOSTS: raise ValueError
    ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local: raise ValueError   # blocks 169.254.169.254
```
Also disable redirects (`allow_redirects=False`) or re-validate each hop; pin the resolved IP to avoid DNS rebinding.
Open redirect: accept only relative paths: `if not target.startswith("/") or target.startswith("//"): target = "/"`, or map keys to URLs.

## 10. Path traversal and uploads
```python
safe = os.path.basename(filename)
path = os.path.realpath(os.path.join(BASE, safe))
if not path.startswith(os.path.realpath(BASE) + os.sep): abort(400)
```
Uploads: server-generated filenames, size limit, extension AND magic-byte check, store outside web root or on object storage with `Content-Disposition: attachment`, never execute. SVG uploads can carry script: sanitize or serve as download. Zip extraction: reject entries with `..` or absolute paths (zip-slip).

## 11. Deserialization and XXE
`pickle`, `marshal`, `yaml.load`, `unserialize`, Java `ObjectInputStream`, `node-serialize`: replace with JSON or `yaml.safe_load`; if unavoidable, authenticate the payload (HMAC) before loading.
XML: use `defusedxml`; Java: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.

## 12. CORS, CSRF, cookies, headers
```js
// Before: app.use(cors({ origin: true, credentials: true }))
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
```
CSRF: cookie-authenticated state-changing routes need a token or `SameSite=Lax/Strict` plus Origin check. Bearer-header APIs are not CSRF-exposed. Never use GET for state changes.
Headers (helmet / SecurityMiddleware): `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `frame-ancestors`/`X-Frame-Options`.

## 13. Data exposure and logging
Return explicit DTOs/serializers; never `res.json(userDoc)` with hash/token fields. Strip stack traces in prod. Do not log bodies, tokens, auth headers, card data; use a redacting logger. Error messages must not reveal whether an account exists. Encrypt sensitive-at-rest fields and backups; use TLS everywhere.

## 14. Races and business logic
Check-then-act on balances, coupons, stock, one-time tokens: use a DB transaction with row lock or atomic conditional update (`UPDATE ... SET used=1 WHERE id=? AND used=0` and check rowcount). Verify price, quantity and discount server-side; never trust client totals. Webhooks: verify provider signatures and idempotency keys (Stripe `constructEvent`). Negative quantities, integer overflow, replay and skipped-step flows belong here.

## 15. LLM and AI features
- Prompt injection: any retrieved page/email/file is untrusted; do not let it trigger tools or reveal secrets. Separate system instructions from data and limit tool permissions to the least needed.
- Never put API keys in the client; proxy through your server with per-user rate limits and budget caps.
- Treat model output as untrusted input: escape before rendering HTML, never `eval`/exec it, never interpolate into SQL/shell.
- Do not log full prompts containing PII; enforce authorization before retrieval (RAG must filter by the caller's permissions).
