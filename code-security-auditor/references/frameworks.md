# Framework and platform checklists

Load only the sections that match the manifests found in Phase 1.

## Contents
Next.js / React / Vite / Vue · Expo / React Native · Express / Node · Flask / FastAPI / Django · Rails · Laravel / PHP · Spring / Java · Go · Supabase · Firebase · Serverless / Vercel / Netlify

## Next.js / React / Vite / Vue
- Secrets: only `NEXT_PUBLIC_*`/`VITE_*` reach the browser. A secret with that prefix is public. Check `next.config.js` `env:` too.
- Route handlers (`app/api/**/route.ts`) and Server Actions are public endpoints: each needs authentication AND ownership checks; validate input with zod. Server Actions are POST endpoints reachable without your UI.
- Middleware-only auth is not enough; re-check in the handler/data layer (and keep Next.js patched; middleware bypass bugs have existed).
- `dangerouslySetInnerHTML`, `href={user}` with `javascript:`, `target="_blank"` without `rel="noopener"`.
- Do not return whole DB rows from `getServerSideProps`/server components into client props: they serialize into the HTML.
- `images.remotePatterns` wildcard allows SSRF-ish proxying; list hosts.
- Auth tokens: prefer HttpOnly cookies over `localStorage`.
- CSP via `headers()` in `next.config`, `poweredByHeader: false`.

## Expo / React Native
- `EXPO_PUBLIC_*` is embedded in the shipped bundle and extractable from the APK/IPA. No secrets, no `service_role`, no third-party secret keys. Use a backend/edge function.
- Store tokens in `expo-secure-store` (Keychain/Keystore), not `AsyncStorage`.
- Android: `usesCleartextTraffic`, `android:allowBackup="true"` (set false for sensitive apps), exported components without permission, debuggable builds.
- iOS: `NSAllowsArbitraryLoads`. Deep links/universal links: validate params, never trust `scheme://` input for auth or navigation to privileged screens.
- WebViews: `originWhitelist={['https://*']}`, avoid `javaScriptEnabled` with untrusted URLs, no `injectedJavaScript` built from user data.
- Ads/analytics SDK IDs are not secrets; payment/AI/admin keys are.
- Logging: strip `console.log` of tokens in production builds.
- In-app purchase/subscription state must be verified server-side (RevenueCat webhook / receipt validation), not trusted from the client flag.
- Permissions: request the minimum (also avoids store-policy rejections).

## Express / Node
- `helmet()`, `express-rate-limit` on auth and expensive routes, body size limits (`express.json({limit})`), `trust proxy` set correctly.
- Validate `req.body/query/params` with zod/joi; never pass them straight to ORM/Mongo filters.
- `cors()` without options reflects nothing but allows all; set an allowlist.
- `res.send(userHtml)` with `text/html` -> XSS; set `Content-Type` properly. `res.redirect(req.query.x)` -> open redirect.
- Prototype pollution: `_.merge`, `Object.assign` with `req.body` into config/objects; block `__proto__`, `constructor`, `prototype` keys.
- `child_process.exec`, `vm.runInNewContext` on user data, `require(userInput)`.
- Error handler must not return `err.stack` in production.
- Sessions: `cookie: {httpOnly, secure, sameSite}`, `resave:false`, store in Redis not MemoryStore.

## Flask / FastAPI / Django
- Flask: `debug=True` (Werkzeug console = RCE), `render_template_string`, hardcoded `SECRET_KEY`, `send_file(request...)`, missing CSRF (Flask-WTF).
- FastAPI: every route needs `Depends(current_user)` plus ownership checks; Pydantic models must exclude privileged fields on input (separate `Create`/`Update`/`Read` schemas); CORS `allow_origins=["*"]` with `allow_credentials=True`.
- Django: `DEBUG=True`, `ALLOWED_HOSTS=['*']`, hardcoded `SECRET_KEY`, `@csrf_exempt`, `mark_safe`, `.raw()`/`.extra()`, `objects.get(pk=request...)` without owner filter, `SECURE_*`/`SESSION_COOKIE_SECURE`/`CSRF_COOKIE_SECURE` unset, DRF `permission_classes = [AllowAny]` or `[]`, serializers with `fields = "__all__"` exposing hashes or flags, `ModelForm` without `fields`.
- Run `python manage.py check --deploy` and report its output.

## Rails
`params.permit` missing (mass assignment), `find(params[:id])` instead of `current_user.records.find`, `html_safe`/`raw`, `where("... #{}")`, `skip_before_action :verify_authenticity_token`, `send_file params[:path]`, `eval`/`constantize` on params, `open(params[:url])`, secrets in `config/secrets.yml`; run Brakeman if available.

## Laravel / PHP
`$request->all()` into `create()` (use `$fillable`/validated()), `DB::raw` with variables, `{!! !!}` in Blade, `unserialize`, `APP_DEBUG=true`, `.env` served from web root, `file_get_contents($_GET[..])`, `include $_GET[..]`, weak `md5` hashing (use `Hash::make`), missing policies/gates on resource routes, `move_uploaded_file` with client filename.

## Spring / Java
`permitAll` over broad matchers, `csrf().disable()` on cookie-session apps, string-built JPQL/native queries, `ObjectInputStream`, XXE-prone parsers, actuator endpoints exposed (`management.endpoints.web.exposure.include=*`), `@RequestBody` entities with privileged fields (use DTOs), Log4j/Spring versions (check advisories), hardcoded creds in `application.properties`.

## Go
`fmt.Sprintf` into SQL, `exec.Command("sh","-c")`, `InsecureSkipVerify`, `http.ServeFile` with joined user paths (use `http.Dir` + `filepath.Clean`/`securejoin`), `math/rand` for tokens (use `crypto/rand`), unbounded `ReadAll`/missing `http.MaxBytesReader`, missing server timeouts (slowloris), template `text/template` for HTML (use `html/template`), goroutine data races on shared auth state.

## Supabase
- RLS must be ENABLED on every table in `public`; a table without RLS is fully readable/writable with the public anon key. Look in `supabase/migrations/*.sql` and any SQL files for `ENABLE ROW LEVEL SECURITY`; absence is a High/Critical finding.
- Policies: avoid `USING (true)` on private data; use `auth.uid() = user_id` for select/insert/update/delete, and `WITH CHECK` on insert/update so users cannot assign rows to others.
- `service_role` key only in server/edge code, never in client bundles or `EXPO_PUBLIC_*`.
- Storage buckets: private by default with per-user path policies; avoid public buckets for user files.
- RPC/SQL functions: `SECURITY DEFINER` functions need `SET search_path` and explicit `auth.uid()` checks.
- Views bypass RLS unless `security_invoker = true`.

## Firebase
- Firestore/Realtime DB/Storage rules: no `if true`; require `request.auth != null` and ownership `request.auth.uid == resource.data.userId`; validate writes (`request.resource.data` fields/types) to stop privilege fields.
- Admin SDK service-account JSON must never ship in the app or repo.
- Restrict API keys (HTTP referrers / bundle IDs / API scope) and enable App Check.
- Cloud Functions callable/HTTP: verify `context.auth` or ID token; do not trust uid from the body.

## Serverless / Vercel / Netlify
Env vars set per environment, not committed; preview deployments inherit secrets - restrict. Edge/API routes are public: auth + rate limits + CORS allowlist. `vercel.json` rewrites/proxies that forward user URLs = SSRF. Webhook endpoints verify signatures. Cron endpoints require a secret header.
