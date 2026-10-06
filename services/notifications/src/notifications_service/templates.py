"""Plain-text email templates rendered in a sandboxed Jinja environment."""

from __future__ import annotations

from typing import Any

from jinja2 import StrictUndefined
from jinja2.sandbox import SandboxedEnvironment

_SIGNATURE = (
    "\n\nPerseus Finance will never ask for your password or one-time codes."
    "\n- The Perseus Security Team"
)

TEMPLATES: dict[str, tuple[str, str]] = {
    "welcome": (
        "Welcome to Perseus Finance",
        "Hi {{ name }},\n\nYour Perseus Finance profile is ready. We recommend enabling "
        "two-factor authentication from your security settings.",
    ),
    "registration_attempt": (
        "Someone tried to register with your email",
        "Hi {{ name }},\n\nSomeone tried to create a new account using your email address. "
        "If this was you, simply sign in. Otherwise you can ignore this message.",
    ),
    "account_locked": (
        "Your account has been temporarily locked",
        "Hi {{ name }},\n\nWe locked your account after several failed sign-in attempts. "
        "It will unlock automatically. If this wasn't you, change your password.",
    ),
    "password_changed": (
        "Your password was changed",
        "Hi {{ name }},\n\nYour password was changed and all sessions were signed out. "
        "If you did not do this, contact support immediately.",
    ),
    "mfa_enabled": (
        "Two-factor authentication enabled",
        "Hi {{ name }},\n\nTwo-factor authentication is now enabled on your account.",
    ),
    "suspicious_session": (
        "Security alert: sessions signed out",
        "Hi {{ name }},\n\nWe detected reuse of an old session token and signed out all "
        "devices. Please sign in again and consider changing your password.",
    ),
    "transfer_sent": (
        "You sent {{ amount }} {{ currency }}",
        "Hi {{ name }},\n\nYour transfer of {{ amount }} {{ currency }} has completed.\n"
        "Reference: {{ transaction_id }}",
    ),
    "transfer_received": (
        "You received {{ amount }} {{ currency }}",
        "Hi {{ name }},\n\nYou received {{ amount }} {{ currency }}.\n"
        "Reference: {{ transaction_id }}",
    ),
    "transfer_held": (
        "Your transfer is being reviewed",
        "Hi {{ name }},\n\nYour transfer of {{ amount }} {{ currency }} is under review. "
        "We'll notify you once it is processed.\nReference: {{ transaction_id }}",
    ),
    "transfer_rejected": (
        "Your transfer could not be completed",
        "Hi {{ name }},\n\nYour transfer of {{ amount }} {{ currency }} was not completed "
        "({{ reason }}).\nReference: {{ transaction_id }}",
    ),
    "deposit_received": (
        "Deposit of {{ amount }} {{ currency }} received",
        "Hi {{ name }},\n\nA deposit of {{ amount }} {{ currency }} has been credited.\n"
        "Reference: {{ transaction_id }}",
    ),
    "account_frozen": (
        "Your account has been frozen",
        "Hi {{ name }},\n\nOne of your accounts has been frozen. Please contact support.",
    ),
}

_env = SandboxedEnvironment(autoescape=False, undefined=StrictUndefined)


def render(template: str, **context: Any) -> tuple[str, str]:
    subject_src, body_src = TEMPLATES[template]
    subject = _env.from_string(subject_src).render(**context)
    body = _env.from_string(body_src).render(**context) + _SIGNATURE
    # Defence in depth against header injection (EmailMessage also rejects newlines).
    subject = " ".join(subject.split())
    return subject, body
