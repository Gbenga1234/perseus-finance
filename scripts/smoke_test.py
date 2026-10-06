"""End-to-end smoke test against the running docker compose stack.

Exercises the public API through the TLS gateway: registration, login, account opening,
an admin deposit, an idempotent transfer, notifications and audit-chain verification,
plus a few negative security checks.

Usage:  make up && uv run python scripts/smoke_test.py
"""

from __future__ import annotations

import os
import shlex
import subprocess  # nosec B404 - fixed argument list, no shell
import sys
import time
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
BASE_URL = os.environ.get("PERSEUS_URL", "https://localhost:8443")
CA = ROOT / "certs" / "perseus-dev-ca.crt"
PASSWORD = "Smoke-Test-Passphrase-" + uuid.uuid4().hex[:8]


def check(condition: bool, message: str) -> None:
    print(("  ok   " if condition else "  FAIL ") + message)
    if not condition:
        sys.exit(1)


# Command prefix that runs the auth CLI; override to run outside docker compose.
AUTH_CLI = shlex.split(
    os.environ.get("PERSEUS_AUTH_CLI", "docker compose exec -T auth python -m auth_service.cli")
)


def create_admin(email: str) -> None:
    subprocess.run(  # noqa: S603  # nosec B603 - fixed argument list, no shell
        [
            *AUTH_CLI,
            "create-user",
            "--email",
            email,
            "--name",
            "Smoke Admin",
            "--role",
            "admin",
            "--role",
            "auditor",
            "--password-stdin",
        ],
        input=PASSWORD + "\n",
        text=True,
        check=True,
        cwd=ROOT,
        capture_output=True,
    )


def main() -> None:
    run = uuid.uuid4().hex[:8]
    alice, bob, admin = (f"{n}-{run}@example.com" for n in ("alice", "bob", "admin"))
    with httpx.Client(base_url=BASE_URL, verify=str(CA), timeout=10) as http:

        def login(email: str) -> dict[str, str]:
            r = http.post("/v1/auth/login", json={"email": email, "password": PASSWORD})
            check(r.status_code == 200, f"login {email.split('-')[0]} -> {r.status_code}")
            return {"Authorization": f"Bearer {r.json()['access_token']}"}

        print("identity")
        for email in (alice, bob):
            r = http.post(
                "/v1/auth/register",
                json={"email": email, "password": PASSWORD, "full_name": "Smoke"},
            )
            check(r.status_code == 202, f"register -> {r.status_code}")
        create_admin(admin)
        a, b, ops = login(alice), login(bob), login(admin)

        print("accounts")
        acct_a = http.post("/v1/accounts", headers=a, json={"currency": "USD"}).json()["id"]
        acct_b = http.post("/v1/accounts", headers=b, json={"currency": "USD"}).json()["id"]
        r = http.get(f"/v1/accounts/{acct_b}", headers=a)
        check(r.status_code == 404, "alice cannot read bob's account")

        print("money movement")
        r = http.post(
            "/v1/ledger/deposits",
            headers={**ops, "Idempotency-Key": uuid.uuid4().hex},
            json={
                "account_id": acct_a,
                "amount": "100.00",
                "currency": "USD",
                "reference": f"smoke-{run}",
            },
        )
        check(r.status_code == 201, f"admin deposit -> {r.status_code}")
        key = uuid.uuid4().hex
        body = {
            "source_account_id": acct_a,
            "destination_account_id": acct_b,
            "amount": "25.50",
            "currency": "USD",
            "description": "smoke test",
        }
        first = http.post("/v1/ledger/transfers", headers={**a, "Idempotency-Key": key}, json=body)
        check(first.status_code == 201, f"transfer -> {first.status_code} {first.text[:120]}")
        replay = http.post("/v1/ledger/transfers", headers={**a, "Idempotency-Key": key}, json=body)
        check(replay.headers.get("idempotent-replayed") == "true", "retry is replayed, not re-run")
        bal_a = http.get(f"/v1/ledger/accounts/{acct_a}/balance", headers=a).json()["balance"]
        bal_b = http.get(f"/v1/ledger/accounts/{acct_b}/balance", headers=b).json()["balance"]
        check((bal_a, bal_b) == ("74.50", "25.50"), f"balances {bal_a} / {bal_b}")
        r = http.post(
            "/v1/ledger/transfers",
            headers={**a, "Idempotency-Key": uuid.uuid4().hex},
            json={**body, "amount": "1000.00"},
        )
        check(
            r.status_code == 422 and r.json()["code"] == "insufficient_funds", "overdraft rejected"
        )

        print("events (outbox -> signed stream -> consumers)")
        deadline = time.time() + 20
        notes: list[dict[str, str]] = []
        while time.time() < deadline:
            notes = http.get("/v1/notifications", headers=b).json()
            if any(n["template"] == "transfer_received" and n["status"] == "sent" for n in notes):
                break
            time.sleep(1)
        check(any(n["template"] == "transfer_received" for n in notes), "bob was notified")
        verify = http.get("/v1/audit/verify", headers=ops).json()
        check(
            verify["valid"] and verify["records_checked"] > 0,
            f"audit chain valid ({verify['records_checked']} records)",
        )

        print("perimeter")
        for path in (
            "/internal/accounts/" + acct_a,
            "/metrics",
            "/health/ready",
            "/docs",
            "/oauth/token",
        ):
            r = http.get(path)
            check(r.status_code == 404, f"{path} not exposed")
        if BASE_URL.startswith("https"):
            check("strict-transport-security" in r.headers, "HSTS header set")
        r = http.get("/v1/accounts", headers={"Authorization": "Bearer forged.token.value"})
        check(r.status_code == 401, "forged token rejected")
    print("\nsmoke test passed")


if __name__ == "__main__":
    main()
