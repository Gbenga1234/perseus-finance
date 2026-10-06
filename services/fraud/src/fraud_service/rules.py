"""Pure, deterministic risk rules. Signals are gathered first, then scored here."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from fraud_service.config import Settings

Decision = Literal["allow", "review", "deny"]


@dataclass(frozen=True)
class RiskContext:
    amount_minor: int
    attempts_in_window: int  # includes the current attempt
    daily_total_minor: int  # approved volume today, excluding this attempt
    known_payee: bool


@dataclass(frozen=True)
class RuleHit:
    rule: str
    score: int


Rule = Callable[[RiskContext, Settings], RuleHit | None]


def hard_limit(ctx: RiskContext, s: Settings) -> RuleHit | None:
    return RuleHit("hard_limit", 100) if ctx.amount_minor > s.hard_limit_minor else None


def large_amount(ctx: RiskContext, s: Settings) -> RuleHit | None:
    return RuleHit("large_amount", 50) if ctx.amount_minor >= s.review_amount_minor else None


def velocity(ctx: RiskContext, s: Settings) -> RuleHit | None:
    return RuleHit("velocity", 40) if ctx.attempts_in_window > s.velocity_max_transfers else None


def daily_volume(ctx: RiskContext, s: Settings) -> RuleHit | None:
    exceeded = ctx.daily_total_minor + ctx.amount_minor > s.daily_limit_minor
    return RuleHit("daily_volume", 40) if exceeded else None


def new_payee(ctx: RiskContext, s: Settings) -> RuleHit | None:
    if ctx.known_payee:
        return None
    if ctx.amount_minor >= s.review_amount_minor // 2:
        return RuleHit("new_payee_large_amount", 30)
    return RuleHit("new_payee", 10)


RULES: tuple[Rule, ...] = (hard_limit, large_amount, velocity, daily_volume, new_payee)


@dataclass(frozen=True)
class Evaluation:
    score: int
    decision: Decision
    hits: tuple[RuleHit, ...]


def evaluate(ctx: RiskContext, settings: Settings, rules: tuple[Rule, ...] = RULES) -> Evaluation:
    hits = tuple(hit for rule in rules if (hit := rule(ctx, settings)) is not None)
    score = min(100, sum(hit.score for hit in hits))
    decision: Decision
    if score >= settings.deny_score:
        decision = "deny"
    elif score >= settings.review_score:
        decision = "review"
    else:
        decision = "allow"
    return Evaluation(score=score, decision=decision, hits=hits)
