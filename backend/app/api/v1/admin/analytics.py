"""
Admin analytics & risk engine endpoints.

Risk thresholds (most conservative):
  critical  : score < 40
  high      : 40 ≤ score < 60
  medium    : 60 ≤ score < 80
  low       : score ≥ 80

Only admin / super_admin roles may access these endpoints.
actor_ip is stored in audit logs but never returned in responses.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.admin.auth import require_admin
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.scan_result import ScanResult
from app.models.site import Site, SiteStatus
from app.models.user import User

router = APIRouter(prefix="/admin/analytics", tags=["admin-analytics"])

# ── Risk thresholds ────────────────────────────────────────────────────────────

_RISK_CRITICAL = 40
_RISK_HIGH = 60
_RISK_MEDIUM = 80


def _risk_level(score: int) -> str:
    if score < _RISK_CRITICAL:
        return "critical"
    if score < _RISK_HIGH:
        return "high"
    if score < _RISK_MEDIUM:
        return "medium"
    return "low"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/summary")
async def get_summary(
    db: AsyncSession = Depends(get_db),
    _admin: User | None = Depends(require_admin),
) -> dict[str, Any]:
    """Platform-wide counts: users, verified sites, scans, risk breakdown."""
    total_users = (await db.execute(select(func.count(User.id)))).scalar_one()
    total_sites = (await db.execute(select(func.count(Site.id)))).scalar_one()
    verified_sites = (
        await db.execute(
            select(func.count(Site.id)).where(Site.status == SiteStatus.active)
        )
    ).scalar_one()
    total_scans = (await db.execute(select(func.count(ScanResult.id)))).scalar_one()

    # Risk distribution from latest scan per site
    latest_scores_q = (
        select(
            ScanResult.site_id,
            func.max(ScanResult.scanned_at).label("last_scan"),
        )
        .group_by(ScanResult.site_id)
        .subquery()
    )
    scores_q = await db.execute(
        select(ScanResult.trust_score).join(
            latest_scores_q,
            (ScanResult.site_id == latest_scores_q.c.site_id)
            & (ScanResult.scanned_at == latest_scores_q.c.last_scan),
        )
    )
    scores = [row[0] for row in scores_q.all()]
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s in scores:
        risk_counts[_risk_level(s)] += 1

    return {
        "total_users": total_users,
        "total_sites": total_sites,
        "verified_sites": verified_sites,
        "total_scans": total_scans,
        "risk_distribution": risk_counts,
    }


@router.get("/risky-sites")
async def get_risky_sites(
    db: AsyncSession = Depends(get_db),
    _admin: User | None = Depends(require_admin),
) -> list[dict[str, Any]]:
    """Return sites with latest trust score < 60 (high/critical risk), most risky first."""
    latest_scores_q = (
        select(
            ScanResult.site_id,
            func.max(ScanResult.scanned_at).label("last_scan"),
        )
        .group_by(ScanResult.site_id)
        .subquery()
    )
    rows = await db.execute(
        select(
            Site.id,
            Site.domain,
            Site.owner_id,
            ScanResult.trust_score,
            ScanResult.scanned_at,
        )
        .join(Site, ScanResult.site_id == Site.id)
        .join(
            latest_scores_q,
            (ScanResult.site_id == latest_scores_q.c.site_id)
            & (ScanResult.scanned_at == latest_scores_q.c.last_scan),
        )
        .where(ScanResult.trust_score < _RISK_HIGH)
        .order_by(ScanResult.trust_score)
        .limit(100)
    )
    return [
        {
            "site_id": str(r.id),
            "domain": r.domain,
            "owner_id": str(r.owner_id),
            "trust_score": r.trust_score,
            "risk_level": _risk_level(r.trust_score),
            "last_scanned_at": r.scanned_at.isoformat(),
        }
        for r in rows.all()
    ]


@router.get("/audit-log")
async def get_audit_log(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _admin: User | None = Depends(require_admin),
) -> list[dict[str, Any]]:
    """Recent audit log entries. actor_ip is intentionally excluded from response."""
    limit = min(limit, 500)
    rows = await db.execute(
        select(AuditLog)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
    )
    return [
        {
            "id": r.id,
            "action": r.action,
            "outcome": r.outcome,
            "actor_id": r.actor_id,
            "actor_role": r.actor_role,
            # actor_ip intentionally omitted
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "details": r.details,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows.scalars().all()
    ]


@router.get("/scan-trends")
async def get_scan_trends(
    days: int = 30,
    db: AsyncSession = Depends(get_db),
    _admin: User | None = Depends(require_admin),
) -> dict[str, Any]:
    """Daily scan counts and average trust scores for the last N days (max 90)."""
    days = min(days, 90)
    since = datetime.now(timezone.utc) - timedelta(days=days)

    rows = await db.execute(
        select(
            func.date_trunc("day", ScanResult.scanned_at).label("day"),
            func.count(ScanResult.id).label("count"),
            func.avg(ScanResult.trust_score).label("avg_score"),
        )
        .where(ScanResult.scanned_at >= since)
        .group_by(func.date_trunc("day", ScanResult.scanned_at))
        .order_by(func.date_trunc("day", ScanResult.scanned_at))
    )
    return {
        "days": days,
        "trend": [
            {
                "date": str(r.day.date()) if r.day else None,
                "scan_count": r.count,
                "avg_trust_score": round(float(r.avg_score), 1) if r.avg_score else None,
            }
            for r in rows.all()
        ],
    }
