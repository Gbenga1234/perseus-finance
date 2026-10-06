"""Operational CLI. Example::

python -m auth_service.cli create-user --email ops@example.com --name "Ops" --role admin
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
import uuid

from perseus_common.db import create_engine, create_sessionmaker
from perseus_common.errors import AppError
from perseus_common.outbox import enqueue_event
from sqlalchemy import select

from auth_service.config import get_settings
from auth_service.models import OutboxEvent, User
from auth_service.passwords import hash_password, validate_password_strength
from auth_service.service import normalize_email

ROLES = ("customer", "admin", "auditor")


def _read_password(from_stdin: bool) -> str | None:
    if from_stdin:  # for automation: never pass passwords as CLI arguments
        return sys.stdin.readline().rstrip("\n")
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Confirm password: "):
        print("Passwords do not match.", file=sys.stderr)
        return None
    return password


async def create_user(email: str, name: str, roles: list[str], password_stdin: bool) -> int:
    email = normalize_email(email)
    password = _read_password(password_stdin)
    if password is None:
        return 1
    try:
        validate_password_strength(password, email)
    except AppError as exc:
        print(exc.detail, file=sys.stderr)
        return 1

    settings = get_settings()
    engine = create_engine(settings)
    try:
        async with create_sessionmaker(engine)() as session:
            if await session.scalar(select(User).where(User.email == email)):
                print("A user with that email already exists.", file=sys.stderr)
                return 1
            user = User(
                id=uuid.uuid4(),
                email=email,
                full_name=name,
                password_hash=await hash_password(password),
                roles=roles,
            )
            session.add(user)
            enqueue_event(
                session,
                OutboxEvent,
                producer=settings.service_name,
                event_type="user.registered",
                actor_id="cli",
                subject_id=str(user.id),
                data={"user_id": str(user.id), "email": email, "full_name": name, "roles": roles},
            )
            await session.commit()
            print(f"Created user {user.id} with roles {roles}")
    finally:
        await engine.dispose()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="auth_service.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-user", help="Create a user (prompts for the password)")
    create.add_argument("--email", required=True)
    create.add_argument("--name", required=True)
    create.add_argument("--role", action="append", choices=ROLES, dest="roles")
    create.add_argument("--password-stdin", action="store_true", help="read password from stdin")
    args = parser.parse_args()
    if args.command == "create-user":
        sys.exit(
            asyncio.run(
                create_user(args.email, args.name, args.roles or ["customer"], args.password_stdin)
            )
        )


if __name__ == "__main__":
    main()
