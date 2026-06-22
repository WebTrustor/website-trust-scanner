import uuid as _uuid
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.exceptions import URLValidationError
from app.core.url_validator import validate_url
from app.db.session import get_db
from app.models.site import Site, SiteStatus
from app.models.user import User
from app.schemas.site import SiteCreate, SiteDetail, SiteVerificationInfo
from app.services.audit_logger import log_event
from app.services.dns_verification import get_expected_txt, verify_ownership

router = APIRouter(prefix="/sites", tags=["sites"])


def _parse_domain(raw: str) -> str:
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    try:
        validate_url(raw)
    except Exception as exc:
        raise URLValidationError(str(exc)) from exc
    return urlparse(raw).hostname or raw.strip()


@router.post("", response_model=SiteDetail, status_code=201)
async def add_site(
    body: SiteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SiteDetail:
    domain = _parse_domain(body.domain.strip())
    site = Site(owner_id=current_user.id, domain=domain)
    db.add(site)
    await db.flush()

    await log_event(
        db,
        action="site.add",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_type="site",
        resource_id=str(site.id),
        details={"domain": domain},
    )

    return SiteDetail.model_validate(site)


@router.get("", response_model=list[SiteDetail])
async def list_sites(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[SiteDetail]:
    result = await db.execute(
        select(Site).where(Site.owner_id == current_user.id).order_by(Site.created_at)
    )
    return [SiteDetail.model_validate(s) for s in result.scalars().all()]


@router.get("/{site_id}", response_model=SiteDetail)
async def get_site(
    site_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SiteDetail:
    uid = _parse_site_id(site_id)
    site = await _get_owned_site(db, uid, current_user)
    return SiteDetail.model_validate(site)


@router.get("/{site_id}/verification", response_model=SiteVerificationInfo)
async def get_verification_info(
    site_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SiteVerificationInfo:
    """Return the TXT record the user must add to prove ownership."""
    uid = _parse_site_id(site_id)
    site = await _get_owned_site(db, uid, current_user)
    return SiteVerificationInfo(
        domain=site.domain,
        txt_record_name="_trustscanner",
        txt_record_value=get_expected_txt(str(site.id)),
        status=site.status,
    )


@router.post("/{site_id}/verify", response_model=SiteDetail)
async def verify_site(
    site_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SiteDetail:
    """Trigger DNS TXT verification. Sets status to 'active' on success."""
    uid = _parse_site_id(site_id)
    site = await _get_owned_site(db, uid, current_user)

    if site.status == SiteStatus.active:
        return SiteDetail.model_validate(site)

    verified = await verify_ownership(site.domain, str(site.id))

    if verified:
        site.status = SiteStatus.active
        await log_event(
            db,
            action="site.verified",
            actor_id=str(current_user.id),
            actor_role=current_user.role.value,
            resource_type="site",
            resource_id=str(site.id),
            details={"domain": site.domain},
        )
    else:
        await log_event(
            db,
            action="site.verify.failed",
            outcome="failure",
            actor_id=str(current_user.id),
            actor_role=current_user.role.value,
            resource_type="site",
            resource_id=str(site.id),
            details={"domain": site.domain},
        )
        raise HTTPException(
            status_code=400,
            detail="DNS TXT record not found. Add the record and try again.",
        )

    return SiteDetail.model_validate(site)


# ── helpers ────────────────────────────────────────────────────────────────────

def _parse_site_id(site_id: str) -> _uuid.UUID:
    try:
        return _uuid.UUID(site_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Site not found")


async def _get_owned_site(
    db: AsyncSession, uid: _uuid.UUID, current_user: User
) -> Site:
    result = await db.execute(
        select(Site).where(Site.id == uid, Site.owner_id == current_user.id)
    )
    site = result.scalar_one_or_none()
    if site is None:
        raise HTTPException(status_code=404, detail="Site not found")
    return site
