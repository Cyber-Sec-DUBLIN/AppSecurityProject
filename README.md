# SlopShop — AppSecurity CA3 Project

A small e-commerce web application built for **DFCS H4013 Application Security
(CA3)**. It is developed in three versions on separate branches so the security
changes between them can be compared.

| Branch | Version | State |
|---|---|---|
| `v0-baseline` | v0 | AI-developed baseline, **before** security hardening (intentionally insecure) |
| `v1-ai-secured` | v1 | After prompting AI to implement the documented security requirements |
| `v2-remediated` | v2 | After independent testing, remediation and regression testing |

Compare versions on GitHub: Pull requests → New pull request → pick two branches.

> ⚠️ **This branch (v0) is intentionally vulnerable.** It is a training
> baseline for a university security assignment. Run it **only on localhost with
> synthetic data**. Do not deploy it, expose it to a network, or enter real
> data. See [`docs/VULNERABILITIES.md`](docs/VULNERABILITIES.md) for the full
> catalogue of deliberate weaknesses.

## What it does

SlopShop is a toy online shop with:

- **Roles:** customer, staff, admin.
- **Auth & sessions:** signup, login, logout, cookie session.
- **CRUD:** products (create/read/delete), orders (create/read), users (read/delete via admin).
- **Access-controlled operation:** the admin user-management area.

Critical flows: register/login → browse/search → cart → checkout (simulated) →
order; staff/admin manage products and users.

## Architecture

```
frontend/  Astro static site (client-side fetch)  ->  :4321
backend/   Rust + Axum JSON API, SQLite (rusqlite) ->  :8080  (slopshop.db)
```

The frontend renders data fetched from the API in the browser. The backend owns
all persistence and business logic. (In v0 the separation is deliberately
undermined by permissive CORS and client-trusted data — see the catalogue.)

## Running locally

**Backend** (needs the Rust toolchain):
```bash
cd backend
cargo run
# SlopShop backend (INSECURE v0) listening on http://127.0.0.1:8080
```

**Frontend** (needs Node 18+):
```bash
cd frontend
npm install
npm run dev
# http://localhost:4321
```

The SQLite database `backend/slopshop.db` is created and seeded automatically on
first run. Delete it to reset.

### Demo accounts

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | admin |
| `staff` | `staff123` | staff |
| `alice` | `password123` | customer |

## Security verification

Reproduce every baseline weakness (backend running on :8080):
```bash
./scripts/verify_v0.sh
```
Each check **passes when the vulnerability is present** — in v1/v2 the same
checks should flip to "mitigated", which makes this script a regression test.

Locate the deliberate flaws in the source:
```bash
grep -rn "VULN-" backend/src frontend/src
```

## Provenance & AI usage

Built with AI assistance per the CA3 brief. The v0 baseline was **deliberately
prompted to be insecure**; this is recorded here and belongs in the group's AI
usage record so the baseline is not mistaken for an accidental or banned
pre-made training application. Stack: Astro (MIT), Axum/Tokio (MIT), rusqlite
(MIT), serde (MIT/Apache-2.0), tower-http (MIT).
