# Security model

## Reporting a vulnerability

Please do not open public issues for security problems. Email the maintainers with details and
reproduction steps; we aim to acknowledge within 2 business days.

## Controls implemented

### Identity & sessions (auth service)
- **Argon2id** password hashing (64 MiB, t=3), run off the event loop; transparent rehash when
  parameters change. Passwords 12–128 chars, common-password and email-containment checks.
- **No account enumeration**: registration returns the same `202` for new and existing emails
  (the existing owner is emailed instead); login errors are generic and timing-equalised with a
  dummy hash for unknown users.
- **Lockout** after 5 failures for 15 minutes, with an email alert. The gateway additionally
  rate-limits credential endpoints to 10 requests/minute per IP.
- **TOTP MFA** with ±1 step drift and **replay protection** (a code's time-step can be used once).
  TOTP secrets are encrypted at rest with Fernet (MultiFernet supports key rotation).
- **Access tokens**: RS256, 10-minute lifetime, `kid` header, `iss`/`aud`/`exp`/`nbf`/`jti`
  required. Algorithm is pinned, defeating `alg=none` and HS256 key-confusion attacks.
- **Refresh tokens**: opaque 384-bit values, stored only as SHA-256 hashes, rotated on every use.
  Replaying a rotated token revokes the whole token family (theft detection). Password change,
  MFA enrolment and "logout everywhere" revoke all sessions.

### Authorization
- Every service verifies tokens itself (**zero trust** — the gateway is not trusted to authenticate).
- User tokens (`aud=perseus-api`) and service tokens (`aud=perseus-internal`, `typ=service`)
  cannot be substituted for each other. Internal endpoints require specific **scopes**
  (`accounts:read`, `fraud:assess`, `ledger:balance:read`); each service client gets only the
  scopes it needs.
- Object-level authorization on every read/write; resources belonging to someone else return
  **404, not 403**, so identifiers cannot be probed (IDOR).
- Request models use `extra="forbid"` — unknown fields such as `roles` or `status` are rejected
  (mass-assignment protection).

### Money integrity (ledger)
- Double-entry: every transaction writes balanced entries (sum = 0).
- Balance rows are locked `SELECT … FOR UPDATE` in a deterministic order (no deadlocks, no lost updates).
- A database `CHECK` constraint forbids negative customer balances even if application logic fails.
- Entries are immutable: a PostgreSQL trigger blocks `UPDATE`/`DELETE`/`TRUNCATE`.
- **Idempotency-Key** is mandatory on money movement; replays return the stored response, and a
  key reused with a different payload is rejected. The response is committed atomically with the postings.
- Amounts are decimal strings converted to integer minor units with exact precision checks.
- **Fail closed**: if the fraud service or its signals store is unavailable, transfers are refused (503).
- Risk scores and rules are never exposed to customers.

### Events & audit
- Events are written through a **transactional outbox** (no lost or phantom events) and
  **HMAC-SHA256 signed**; consumers reject unsigned/tampered events to a dead-letter stream.
- The audit log is a **SHA-256 hash chain**; `/v1/audit/verify` detects modification, deletion or
  reordering. The runtime DB role has only `SELECT, INSERT`, and a trigger blocks mutation even
  for the owner. Export `/v1/audit/head` to an external system periodically to detect truncation.

### Transport, input & output
- TLS 1.2/1.3 only at the gateway with modern ciphers, HSTS, no session tickets; Let's Encrypt
  certificates via certbot. Requests for unknown hostnames are rejected during the TLS handshake.
- 64 KB body limit (gateway and app, including chunked bodies), header/body timeouts,
  per-IP connection and request rate limits, stricter limits on money endpoints.
- `TrustedHostMiddleware`, strict security headers (`CSP default-src 'none'`, `nosniff`,
  `frame-ancestors 'none'`, `Cache-Control: no-store`), no `Server` header.
- Errors use RFC 9457 problem+json; validation errors never echo input values; unhandled errors
  return a generic message with a request id.
- Notification emails are plain text rendered in a sandboxed Jinja environment; header injection
  is prevented.

### Secrets & configuration
- Secrets are never committed or baked into images: locally they live in the git-ignored `.env`
  (mode 600) and are injected as environment variables by Compose. Gateway TLS certificates
  come from certbot (Let's Encrypt) and are mounted read-only. Note that environment variables are visible to
  anyone who can run `docker inspect`, so restrict Docker access and use a secret manager
  in production.
- Services refuse to start in `production`/`staging` with unsafe settings (missing or short keys,
  `*` hosts/origins, DB TLS disabled, test DB overrides, SMTP without TLS).
- Logs are structured JSON with recursive redaction of passwords, tokens, secrets and
  authorization headers; the gateway logs paths without query strings.

### Infrastructure
- Containers: non-root UID 10001, read-only root filesystem, all capabilities dropped,
  `no-new-privileges`, resource limits, health checks. Minimal slim base image, patched at build.
- Package managers (`apt`, `dpkg`, `pip`) are removed from service images so a compromised
  container cannot install tooling. A shell (`sh`/`bash`) is deliberately kept for production
  maintenance via `docker exec`; the dpkg package database is kept so Trivy can still scan.
- Network: only the gateway publishes ports (80 for ACME/redirect, 443); services and data stores sit on
  an `internal` network with no internet egress. `/internal`, `/metrics` and `/health` are not routed.
- PostgreSQL: one database per service, SCRAM-SHA-256, separate **migrator** (DDL) and **app**
  (DML only) roles; migrations run in one-shot containers so app containers never hold DDL rights.
- Redis: password-protected, dangerous commands (`FLUSHALL`, `CONFIG`, `DEBUG`…) disabled.
- Local checks (`make check`): ruff (incl. bandit rules), mypy, tests, bandit, pip-audit;
  gitleaks via pre-commit. Dependabot proposes Python, Actions and Docker updates.
  There is no CI gate: deployment workflows push images without tests or image scans.

## Hardening checklist for a real deployment

- [ ] Use a managed secret store (Vault / AWS Secrets Manager / GCP Secret Manager) and rotate
      the JWT key, event key, client secrets and DB passwords regularly. JWKS supports multiple
      keys; publish the new key before signing with it.
- [ ] Enable TLS to PostgreSQL and Redis (`DB_SSLMODE=verify-full`, `rediss://`) and mTLS or a
      service mesh between services.
- [ ] Use per-producer asymmetric event signatures (or a broker with ACLs) instead of one shared HMAC key.
- [ ] Put a WAF / DDoS protection in front of the gateway; rate-limit by user as well as IP.
- [ ] Add email verification and a breached-password check (k-anonymity HIBP API) at registration.
- [ ] Anchor the audit head hash externally (e.g. WORM object storage) on a schedule.
- [ ] Add a CI gate (tests, pip-audit, gitleaks, Trivy) that must pass before images are pushed.
- [ ] Pin GitHub Actions to commit SHAs and sign images (cosign) with SBOMs.
- [ ] Define data-retention and PII policies (audit and notification data contain personal data).
