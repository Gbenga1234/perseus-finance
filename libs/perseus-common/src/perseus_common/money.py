"""Money handling. Amounts are integers in the currency's minor unit; never floats."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

# ISO 4217 currencies supported by the platform and their minor-unit exponents.
CURRENCY_EXPONENTS: dict[str, int] = {
    "USD": 2,
    "EUR": 2,
    "GBP": 2,
    "NGN": 2,
    "CAD": 2,
    "CHF": 2,
    "JPY": 0,
    "KWD": 3,
}

AMOUNT_PATTERN = r"^\d{1,15}(\.\d{1,3})?$"
_AMOUNT_RE = re.compile(AMOUNT_PATTERN)
MAX_MINOR_UNITS = 10**17  # comfortably inside a signed 64-bit integer


class MoneyError(ValueError):
    pass


def validate_currency(code: str) -> str:
    code = code.upper()
    if code not in CURRENCY_EXPONENTS:
        raise MoneyError(f"Unsupported currency: {code}")
    return code


def to_minor_units(amount: str, currency: str) -> int:
    """Convert a decimal string (e.g. ``"10.50"``) to minor units, rejecting precision loss."""
    if not _AMOUNT_RE.match(amount):
        raise MoneyError("Amount must be a positive decimal string")
    exponent = CURRENCY_EXPONENTS[validate_currency(currency)]
    try:
        value = Decimal(amount)
    except InvalidOperation as exc:
        raise MoneyError("Invalid amount") from exc
    scaled = value.scaleb(exponent)
    if scaled != scaled.to_integral_value():
        raise MoneyError(f"{currency} supports at most {exponent} decimal places")
    minor = int(scaled)
    if minor <= 0:
        raise MoneyError("Amount must be greater than zero")
    if minor > MAX_MINOR_UNITS:
        raise MoneyError("Amount is too large")
    return minor


def format_minor_units(minor: int, currency: str) -> str:
    exponent = CURRENCY_EXPONENTS[validate_currency(currency)]
    value = Decimal(minor).scaleb(-exponent)
    return f"{value:.{exponent}f}"
