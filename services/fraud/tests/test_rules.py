import pytest
from fraud_service.config import Settings
from fraud_service.rules import RiskContext, evaluate

SETTINGS = Settings(environment="test")


def ctx(amount=1_000, attempts=1, daily=0, known=True) -> RiskContext:
    return RiskContext(amount, attempts, daily, known)


@pytest.mark.parametrize(
    ("context", "decision", "rules"),
    [
        (ctx(), "allow", []),
        (ctx(known=False), "allow", ["new_payee"]),
        (ctx(amount=SETTINGS.review_amount_minor), "review", ["large_amount"]),
        (ctx(amount=SETTINGS.hard_limit_minor + 1), "deny", None),
        (ctx(attempts=SETTINGS.velocity_max_transfers + 1), "allow", ["velocity"]),
        (
            ctx(attempts=SETTINGS.velocity_max_transfers + 1, known=False),
            "review",
            ["velocity", "new_payee"],
        ),
        (
            ctx(amount=SETTINGS.review_amount_minor, daily=SETTINGS.daily_limit_minor),
            "deny",
            ["large_amount", "daily_volume"],
        ),
    ],
)
def test_rule_outcomes(context, decision, rules):
    result = evaluate(context, SETTINGS)
    assert result.decision == decision
    assert 0 <= result.score <= 100
    if rules is not None:
        assert [h.rule for h in result.hits] == rules
