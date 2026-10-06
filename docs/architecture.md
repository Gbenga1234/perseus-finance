# Architecture decisions

## Service boundaries and data ownership
Each service owns its database; no service reads another's tables. Synchronous calls are
limited to what a request needs *now* (the ledger must know account ownership and a risk
decision before moving money); everything else is propagated by events.

Balances live in the **ledger**, not in accounts. Account metadata (owner, status, currency)
lives in **accounts**. This keeps every money movement inside one database transaction —
no distributed transactions.

## Transfer flow
1. Client `POST /v1/ledger/transfers` with an `Idempotency-Key`.
2. Ledger claims the key (short transaction), then fetches both accounts from accounts
   (`/internal/accounts/{id}`, scope `accounts:read`) and checks ownership, status, currency.
3. Ledger asks fraud for a decision (`/internal/assessments`, scope `fraud:assess`).
   `deny` → transaction recorded as rejected (422). `review` → held (202) for an admin.
   Fraud unavailable → 503, nothing recorded, key released for a safe retry.
4. `allow` → balance rows locked in sorted order, funds checked, two entries written,
   balances updated, outbox event added, idempotency response stored — one commit.
5. The outbox relay publishes the signed `transfer.completed` event; notifications emails both
   parties, audit appends it to the hash chain.

## Events
Envelope: `id, type, version, producer, occurred_at, actor_id, subject_id, data`, JSON-encoded,
HMAC-signed. Delivery is at-least-once through a single Redis Stream with one consumer group per
consuming service; handlers are idempotent (audit dedupes on `event_id`, notifications on
`(event_id, user, template)`). Failed messages are retried after 60 s idle and dead-lettered to
`perseus:events:dlq` after 5 deliveries.

| Producer | Events |
|---|---|
| auth | `user.registered`, `user.registration_attempted`, `user.login_succeeded`, `user.login_failed`, `user.locked`, `user.password_changed`, `user.mfa_enabled`, `user.refresh_token_reuse_detected`, `user.logged_out` |
| accounts | `account.opened`, `account.frozen`, `account.unfrozen`, `account.closed` |
| ledger | `transfer.completed`, `transfer.held`, `transfer.rejected`, `deposit.completed`, `deposit.rejected` |
| fraud | `fraud.flagged` |

## Why these choices
- **FastAPI + async SQLAlchemy 2 + asyncpg**: typed, fast, mature; Pydantic gives strict input validation.
- **Redis Streams** instead of Kafka/RabbitMQ: consumer groups, acks and replay with one
  dependency already needed for fraud signals. Swap for Kafka at higher scale; the
  publisher/consumer interfaces are small.
- **Pessimistic locking** for balances: correctness over throughput for hot accounts; simple to
  reason about. Very hot accounts could later move to sharded sub-balances.
- **Integer minor units** for money; decimal strings at the API boundary.
- **uv workspace**: one lockfile for reproducible builds; each image installs only its service.

## Scaling notes
Services are stateless (state in Postgres/Redis) and can scale horizontally. The outbox relay
uses `FOR UPDATE SKIP LOCKED`, consumers use consumer groups, and the audit chain serialises
appends with a PostgreSQL advisory lock, so multiple replicas are safe. Set `WEB_CONCURRENCY`
for multiple worker processes per container.
