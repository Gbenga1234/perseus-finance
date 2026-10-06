"""Make ledger entries append-only at the database level.

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE FUNCTION forbid_entry_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'ledger entries are immutable (% blocked)', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER entries_immutable
        BEFORE UPDATE OR DELETE ON entries
        FOR EACH ROW EXECUTE FUNCTION forbid_entry_mutation();
        """
    )
    op.execute(
        """
        CREATE TRIGGER entries_no_truncate
        BEFORE TRUNCATE ON entries
        FOR EACH STATEMENT EXECUTE FUNCTION forbid_entry_mutation();
        """
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("DROP TRIGGER IF EXISTS entries_no_truncate ON entries")
    op.execute("DROP TRIGGER IF EXISTS entries_immutable ON entries")
    op.execute("DROP FUNCTION IF EXISTS forbid_entry_mutation()")
