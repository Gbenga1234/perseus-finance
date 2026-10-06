"""Make audit records append-only at the database level.

Complements the runtime role's SELECT/INSERT-only grants: even the table owner cannot
UPDATE, DELETE or TRUNCATE without first dropping the trigger (itself an audited DDL).

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
        CREATE FUNCTION forbid_audit_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit records are append-only (% blocked)', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_records_append_only
        BEFORE UPDATE OR DELETE ON audit_records
        FOR EACH ROW EXECUTE FUNCTION forbid_audit_mutation();
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_records_no_truncate
        BEFORE TRUNCATE ON audit_records
        FOR EACH STATEMENT EXECUTE FUNCTION forbid_audit_mutation();
        """
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("DROP TRIGGER IF EXISTS audit_records_no_truncate ON audit_records")
    op.execute("DROP TRIGGER IF EXISTS audit_records_append_only ON audit_records")
    op.execute("DROP FUNCTION IF EXISTS forbid_audit_mutation()")
