# Perseus Finance

A security-focused, production-grade Python fintech backend made of six microservices:
customer identity, accounts, a double-entry ledger, real-time fraud scoring,
notifications and a tamper-evident audit trail.

```
                          ┌──────────────────────────────┐
  client ── HTTPS ──────▶ │ gateway (nginx)              │ TLS 1.2+/HSTS, rate limits,
                          │ only public /v1 routes       │ 64 KB body cap, request ids
                          └──────────────┬───────────────┘
            ┌──────────────┬─────────────┼──────────────┬──────────────┬──────────────┐
            ▼              ▼             ▼              ▼              ▼              ▼
          auth         accounts       ledger         fraud       notifications     audit
     (JWT RS256,     (lifecycle,   (double-entry,  (risk rules,  (email from     (hash-chained,
      MFA, OAuth2     freeze,       idempotency,    velocity,     events)         append-only)
      client creds)   close)        fail-closed)    limits)
            │              │  ▲   service tokens ▲  │                ▲              ▲
            │              └──┼──── /internal ───┼──┘                │              │
            └─ outbox ─┬──────┴── outbox ────────┴── outbox ─▶ Redis Stream (HMAC-signed events)
                       │
                 PostgreSQL: one database + two roles (migrator / app) per service
```

| Service | Responsibility | Owns |
|---|---|---|
| **auth** | Registration, Argon2id passwords, TOTP MFA, lockout, RS256 JWTs, rotating refresh tokens with reuse detection, OAuth2 client-credentials for services, JWKS | `users`, `refresh_tokens` |
| **accounts** | Open / rename / freeze / close accounts, Luhn account numbers | `accounts` |
| **ledger** | Double-entry postings, balances, transfers, deposits, review queue, `Idempotency-Key` | `balances`, `transactions`, `entries` |
| **fraud** | Rule-based risk scoring (hard limit, large amount, velocity, daily volume, new payee) | `assessments` |
| **notifications** | Consumes events, sends email (STARTTLS), deduplicated per event | `recipients`, `notifications` |
| **audit** | Consumes every event into a SHA-256 hash chain; verify & search APIs | `audit_records` |

## Quick start

Requirements: Docker (Compose v2), [uv](https://docs.astral.sh/uv/), make.

```bash
make install        # local virtualenv with all packages + dev tools
make check          # lint, type-check, tests, bandit, pip-audit
make secrets        # generate .env: all secrets + local settings (git-ignored)
make dev-cert       # self-signed localhost certificate (local only; prod uses certbot)
make up             # build and start the stack (+ Mailpit) at https://localhost:8443
make admin EMAIL=ops@example.com NAME="Ops Admin"   # bootstrap an admin (prompts for password)
make smoke          # end-to-end test through the gateway
```

Mailpit (captured emails, dev profile only) is at http://127.0.0.1:8025. Locally the gateway
uses a self-signed certificate, so pass `-k` to curl; in production certbot provides a
trusted certificate and no flag is needed.

### Configuration and secrets

All secrets live in a single **`.env`** file that is listed in `.gitignore`. Docker Compose
reads it automatically and injects each value with `${VAR}` interpolation; a missing value
stops `docker compose up` with an error. `.env.example` (committed) documents every variable.
Rotate everything with `uv run python scripts/generate_secrets.py --force`.

### Production TLS (certbot)

The gateway reads certificates from certbot's standard layout,
`$LETSENCRYPT_DIR/live/$DOMAIN/{fullchain,privkey}.pem`, mounted read-only, and serves
ACME HTTP-01 challenges from `$CERTBOT_WEBROOT` on port 80. Certbot runs on the host.

1. Point DNS for your domain at the server and set the production values from
   `.env.example` in `.env` (`DOMAIN`, `GATEWAY_BIND=0.0.0.0`, `HTTP_PORT=80`,
   `HTTPS_PORT=443`, `LETSENCRYPT_DIR=/etc/letsencrypt`, `CERTBOT_WEBROOT=/var/www/certbot`).
2. Issue the first certificate before the gateway exists (port 80 must be free):
   ```bash
   sudo certbot certonly --standalone -d api.example.com
   ```
3. Switch renewals to the webroot so they work while nginx is running: in
   `/etc/letsencrypt/renewal/api.example.com.conf` set `authenticator = webroot` and add
   `webroot_path = /var/www/certbot` (create the directory first).
4. Reload nginx after each renewal:
   ```bash
   sudo certbot renew --dry-run
   # /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh:
   #   docker compose -f /srv/perseus/compose.yml exec -T gateway nginx -s reload
   ```
5. Start without dev-only services: `make up-prod`.
   Hostnames other than `$DOMAIN` are refused (TLS handshake rejected, HTTP closed).

### Example flow

```bash
API=https://localhost:8443; CA="-k"  # self-signed locally; omit in production
curl $CA -X POST $API/v1/auth/register -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"Correct-Horse-Battery-9","full_name":"Ada"}'
TOKEN=$(curl -s $CA -X POST $API/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"Correct-Horse-Battery-9"}' | jq -r .access_token)
curl $CA -X POST $API/v1/accounts -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"currency":"USD"}'
curl $CA -X POST $API/v1/ledger/transfers -H "authorization: Bearer $TOKEN" \
  -H "Idempotency-Key: $(uuidgen)" -H 'content-type: application/json' \
  -d '{"source_account_id":"…","destination_account_id":"…","amount":"25.00","currency":"USD"}'
```

Amounts are **decimal strings** (`"25.00"`); JSON numbers are rejected so floats never touch money.
Internally all money is stored as integer minor units.

## API surface (via gateway)

| Method & path | Who |
|---|---|
| `POST /v1/auth/register` · `login` · `refresh` · `logout` | public |
| `GET /v1/auth/me` · `POST /v1/auth/password` · `mfa/setup` · `mfa/enable` · `logout-all` | user |
| `GET /.well-known/jwks.json` | public |
| `POST/GET /v1/accounts` · `GET/PATCH /v1/accounts/{id}` · `POST …/close` | customer (own accounts) |
| `POST /v1/accounts/{id}/freeze` · `unfreeze` | admin |
| `POST /v1/ledger/transfers` (requires `Idempotency-Key`) | customer |
| `GET /v1/ledger/transfers/{id}` · `GET /v1/ledger/accounts/{id}/balance` · `entries` | parties / admin |
| `POST /v1/ledger/deposits` · `GET …/transfers/pending-review` · `POST …/{id}/approve` · `reject` | admin |
| `GET /v1/fraud/assessments` | admin, auditor |
| `GET /v1/notifications` | user (own) |
| `GET /v1/audit/events` · `verify` · `head` | auditor, admin |

Service-to-service endpoints live under `/internal/*`, require a service token with a specific
scope, and are never routed by the gateway. OpenAPI docs are served at `/docs` on each service
only when `ENVIRONMENT` is `development` or `test`.

## Repository layout

```
libs/perseus-common/      shared: config, JWT verification, middleware, errors, db, events,
                          outbox, money, service client, app factory, test helpers
services/<name>/          src/<name>_service/  tests/  migrations/  alembic.ini  Dockerfile
infra/nginx/              gateway config (+ templates/ rendered with $DOMAIN)
infra/postgres/init/      per-service databases and least-privilege roles
scripts/                  .env secret generation, smoke test
.env.example              every configuration/secret variable (real values go in .env)
docker-compose.yml        production-like local stack
```

## Development

```bash
uv run pytest services/ledger/tests          # one service
uv run pytest -k idempotent                   # by keyword
cd services/ledger && ENVIRONMENT=development DATABASE_URL_OVERRIDE=sqlite+aiosqlite:///dev.db \
  uv run alembic revision --autogenerate -m "describe change"
```

Each service has its own Dockerfile. Build an image from the repository root (the shared
library and `uv.lock` live there); only that service's code enters the build context:

```bash
docker build -f services/ledger/Dockerfile -t perseus/ledger .
```

Tests run in-process against SQLite with real JWT signing/verification; CI additionally runs
every migration (upgrade → drift check → downgrade → upgrade) against PostgreSQL 16, scans for
secrets (gitleaks) and vulnerable dependencies (pip-audit), and scans each image with Trivy.

See [SECURITY.md](SECURITY.md) for the security model and [docs/architecture.md](docs/architecture.md)
for design decisions.
