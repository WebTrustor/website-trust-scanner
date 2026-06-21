import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class DoNotScan(Base):
    """
    Domains that must never be scanned under any circumstance.

    The unique index is on lower(domain) so lookups and inserts are
    case-insensitive without requiring callers to normalise the domain first.
    """

    __tablename__ = "do_not_scan"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # Case-insensitive unique index — the core SSRF/policy guard
        Index("ix_do_not_scan_domain_lower", func.lower(domain), unique=True),
    )

    def __repr__(self) -> str:
        return f"<DoNotScan domain={self.domain!r}>"
