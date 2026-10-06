"""Authentication business logic."""

from __future__ import annotations

import hmac
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import pyotp
from perseus_common.errors import ConflictError, NotFoundError, UnauthorizedError
from perseus_common.logging import get_logger
from perseus_common.outbox import enqueue_event
from perseus_common.timeutil import utcnow
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.config import Settings
from auth_service.crypto import FieldCipher, TokenIssuer, hash_refresh_token, new_refresh_token
from auth_service.models import OutboxEvent, RefreshToken, User
from auth_service.passwords import (
    DUMMY_HASH,
    hash_password,
    validate_password_strength,
    verify_password,
)

log = get_logger(__name__)

INVALID_CREDENTIALS = "Invalid email or password."


@dataclass(frozen=True)
class RequestMeta:
    ip: str | None
    user_agent: str | None


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    expires_in: int
    refresh_expires_in: int


def normalize_email(email: str) -> str:
    return email.strip().lower()


class AuthService:
    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        issuer: TokenIssuer,
        cipher: FieldCipher,
    ) -> None:
        self.session = session
        self.settings = settings
        self.issuer = issuer
        self.cipher = cipher

    # -- helpers -------------------------------------------------------------------

    def _emit(self, event_type: str, user_id: uuid.UUID, **data: Any) -> None:
        enqueue_event(
            self.session,
            OutboxEvent,
            producer=self.settings.service_name,
            event_type=event_type,
            actor_id=str(user_id),
            subject_id=str(user_id),
            data={"user_id": str(user_id), **data},
        )

    def _invalid_credentials(self) -> UnauthorizedError:
        return UnauthorizedError(INVALID_CREDENTIALS, code="invalid_credentials")

    async def _get_user(self, user_id: uuid.UUID) -> User:
        user = await self.session.get(User, user_id)
        if user is None or not user.is_active:
            raise NotFoundError("User not found")
        return user

    def _issue_pair(
        self, user: User, family_id: uuid.UUID, meta: RequestMeta, amr: list[str]
    ) -> tuple[TokenPair, RefreshToken]:
        refresh, refresh_hash = new_refresh_token()
        record = RefreshToken(
            id=uuid.uuid4(),
            user_id=user.id,
            family_id=family_id,
            token_hash=refresh_hash,
            expires_at=utcnow() + timedelta(seconds=self.settings.refresh_token_ttl_seconds),
            created_ip=meta.ip,
            user_agent=meta.user_agent,
        )
        self.session.add(record)
        pair = TokenPair(
            access_token=self.issuer.access_token(user.id, user.roles, amr),
            refresh_token=refresh,
            expires_in=self.settings.access_token_ttl_seconds,
            refresh_expires_in=self.settings.refresh_token_ttl_seconds,
        )
        return pair, record

    async def _revoke_where(self, *criteria: Any) -> None:
        await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.revoked_at.is_(None), *criteria)
            .values(revoked_at=utcnow())
        )

    def _verify_totp(self, user: User, code: str) -> bool:
        """Verify a TOTP code allowing ±1 step of clock drift, rejecting replays."""
        if not user.mfa_secret_encrypted:
            return False
        totp = pyotp.TOTP(self.cipher.decrypt(user.mfa_secret_encrypted))
        current = totp.timecode(utcnow())
        for timecode in (current - 1, current, current + 1):
            if hmac.compare_digest(totp.generate_otp(timecode), code):
                if user.last_totp_timecode is not None and timecode <= user.last_totp_timecode:
                    return False
                user.last_totp_timecode = timecode
                return True
        return False

    async def _record_failure(self, user: User, meta: RequestMeta, reason: str) -> None:
        user.failed_login_count += 1
        self._emit("user.login_failed", user.id, reason=reason, ip=meta.ip)
        if user.failed_login_count >= self.settings.max_failed_logins:
            user.locked_until = utcnow() + timedelta(minutes=self.settings.lockout_minutes)
            user.failed_login_count = 0
            self._emit("user.locked", user.id, locked_until=user.locked_until.isoformat())
            log.warning("account_locked", user_id=str(user.id))
        await self.session.commit()

    # -- use cases ------------------------------------------------------------------

    async def register(self, email: str, password: str, full_name: str) -> None:
        """Create a customer account.

        The response is identical whether or not the email already exists (no account
        enumeration); the existing owner is notified of the attempt instead.
        """
        email = normalize_email(email)
        validate_password_strength(password, email)
        password_hash = await hash_password(password)  # always hash: equal timing

        existing = await self.session.scalar(select(User).where(User.email == email))
        if existing is not None:
            self._emit("user.registration_attempted", existing.id)
            await self.session.commit()
            return

        user = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=password_hash,
            full_name=full_name,
            roles=["customer"],
        )
        self.session.add(user)
        self._emit("user.registered", user.id, email=email, full_name=full_name)
        try:
            await self.session.commit()
        except IntegrityError:
            # Lost a race with a concurrent registration for the same email.
            await self.session.rollback()

    async def login(
        self, email: str, password: str, totp_code: str | None, meta: RequestMeta
    ) -> TokenPair:
        email = normalize_email(email)
        user = await self.session.scalar(select(User).where(User.email == email))
        if user is None:
            await verify_password(DUMMY_HASH, password)
            log.info("login_unknown_email")
            raise self._invalid_credentials()

        now = utcnow()
        if user.locked_until and user.locked_until > now:
            await verify_password(DUMMY_HASH, password)
            self._emit("user.login_failed", user.id, reason="locked", ip=meta.ip)
            await self.session.commit()
            raise self._invalid_credentials()

        ok, needs_rehash = await verify_password(user.password_hash, password)
        if not ok:
            await self._record_failure(user, meta, "bad_password")
            raise self._invalid_credentials()
        if not user.is_active:
            raise self._invalid_credentials()

        amr = ["pwd"]
        if user.mfa_enabled:
            if not totp_code:
                raise UnauthorizedError("A one-time code is required.", code="mfa_required")
            if not self._verify_totp(user, totp_code):
                await self._record_failure(user, meta, "bad_totp")
                raise UnauthorizedError("Invalid one-time code.", code="mfa_invalid")
            amr.append("otp")

        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        if needs_rehash:
            user.password_hash = await hash_password(password)
        pair, _ = self._issue_pair(user, uuid.uuid4(), meta, amr)
        self._emit("user.login_succeeded", user.id, ip=meta.ip, mfa=user.mfa_enabled)
        await self.session.commit()
        return pair

    async def refresh(self, token: str, meta: RequestMeta) -> TokenPair:
        record = await self.session.scalar(
            select(RefreshToken)
            .where(RefreshToken.token_hash == hash_refresh_token(token))
            .with_for_update()
        )
        if record is None:
            raise UnauthorizedError("Invalid refresh token.", code="invalid_refresh_token")

        if record.revoked_at is not None:
            if record.replaced_by_id is not None:
                # A rotated token was replayed: assume theft and kill the whole family.
                await self._revoke_where(RefreshToken.family_id == record.family_id)
                self._emit(
                    "user.refresh_token_reuse_detected",
                    record.user_id,
                    family_id=str(record.family_id),
                    ip=meta.ip,
                )
                await self.session.commit()
                log.warning("refresh_token_reuse", user_id=str(record.user_id))
            raise UnauthorizedError("Invalid refresh token.", code="invalid_refresh_token")

        if record.expires_at <= utcnow():
            raise UnauthorizedError("Refresh token expired.", code="invalid_refresh_token")

        user = await self.session.get(User, record.user_id)
        if user is None or not user.is_active:
            raise UnauthorizedError("Invalid refresh token.", code="invalid_refresh_token")

        amr = ["pwd", "otp"] if user.mfa_enabled else ["pwd"]
        pair, new_record = self._issue_pair(user, record.family_id, meta, amr)
        record.revoked_at = utcnow()
        record.replaced_by_id = new_record.id
        await self.session.commit()
        return pair

    async def logout(self, token: str) -> None:
        record = await self.session.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(token))
        )
        if record is None:
            return
        await self._revoke_where(RefreshToken.family_id == record.family_id)
        self._emit("user.logged_out", record.user_id)
        await self.session.commit()

    async def logout_all(self, user_id: uuid.UUID) -> None:
        await self._revoke_where(RefreshToken.user_id == user_id)
        self._emit("user.logged_out", user_id, all_sessions=True)
        await self.session.commit()

    async def get_profile(self, user_id: uuid.UUID) -> User:
        return await self._get_user(user_id)

    async def change_password(self, user_id: uuid.UUID, current: str, new: str) -> None:
        user = await self._get_user(user_id)
        ok, _ = await verify_password(user.password_hash, current)
        if not ok:
            raise UnauthorizedError("Current password is incorrect.", code="invalid_credentials")
        validate_password_strength(new, user.email)
        user.password_hash = await hash_password(new)
        user.password_changed_at = utcnow()
        await self._revoke_where(RefreshToken.user_id == user.id)
        self._emit("user.password_changed", user.id)
        await self.session.commit()

    async def mfa_setup(self, user_id: uuid.UUID) -> tuple[str, str]:
        user = await self._get_user(user_id)
        if user.mfa_enabled:
            raise ConflictError("MFA is already enabled.", code="mfa_already_enabled")
        secret = pyotp.random_base32()
        user.mfa_secret_encrypted = self.cipher.encrypt(secret)
        user.last_totp_timecode = None
        await self.session.commit()
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=user.email, issuer_name=self.settings.mfa_issuer_name
        )
        return secret, uri

    async def mfa_enable(self, user_id: uuid.UUID, code: str) -> None:
        user = await self._get_user(user_id)
        if user.mfa_enabled:
            raise ConflictError("MFA is already enabled.", code="mfa_already_enabled")
        if not user.mfa_secret_encrypted or not self._verify_totp(user, code):
            raise UnauthorizedError("Invalid one-time code.", code="mfa_invalid")
        user.mfa_enabled = True
        # Existing sessions were established without MFA: end them.
        await self._revoke_where(RefreshToken.user_id == user.id)
        self._emit("user.mfa_enabled", user.id)
        await self.session.commit()
