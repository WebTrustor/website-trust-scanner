"""security_foundation: do_not_scan and audit_logs tables

Revision ID: 001
Revises:
Create Date: 2026-06-21
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── do_not_scan ──────────────────────────────────────────────────────────
    op.create_table(
        "do_not_scan",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("added_by", sa.String(255), nullable=True),
        sa.Column(
            "added_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    # Case-insensitive unique index — the core policy guard
    op.create_index(
        "ix_do_not_scan_domain_lower",
        "do_not_scan",
        [sa.text("lower(domain)")],
        unique=True,
    )

    # ── audit_logs ───────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column(
            "id",
            sa.BigInteger,
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("actor_id", sa.String(36), nullable=True),
        sa.Column("actor_role", sa.String(50), nullable=True),
        sa.Column("actor_ip", INET, nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=True),
        sa.Column("resource_id", sa.String(36), nullable=True),
        sa.Column("details", JSONB, nullable=True),
        sa.Column("outcome", sa.String(20), nullable=False, server_default="success"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    # Fast lookup by actor and by action for forensic queries
    op.create_index("ix_audit_logs_actor_id", "audit_logs", ["actor_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # Revoke DELETE on audit_logs at the DB level via a comment marker.
    # The actual REVOKE must be run once by a DBA:
    #   REVOKE DELETE ON audit_logs FROM trustscanner_app;
    # Recorded here so it is not forgotten.


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("do_not_scan")
