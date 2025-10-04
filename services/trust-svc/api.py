"""Trust Service REST API endpoints."""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .database import get_async_session
from .models import CSCA, DSC, MasterList, CRL, Source, Provenance
from .metrics import record_api_request, update_trusted_csca_count, update_trusted_dsc_count
from .schemas import (
    TrustStatusResponse, TrustSnapshotResponse, TrustAnchorsResponse,
    TrustAnchor, TrustSnapshotEntry, ApiResponse
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/trust/status",
    response_model=TrustStatusResponse,
    summary="Get trust service status",
    description="Returns the current status and health of the trust service including data freshness"
)
async def get_trust_status(
    session: AsyncSession = Depends(get_async_session)
) -> TrustStatusResponse:
    """Get trust service status with data freshness information."""
    
    try:
        # Get latest master list updates by country
        master_list_query = (
            select(
                MasterList.country_code,
                func.max(MasterList.updated_at).label('latest_update'),
                func.count(MasterList.id).label('total_lists')
            )
            .group_by(MasterList.country_code)
        )
        master_list_result = await session.execute(master_list_query)
        master_lists_data = master_list_result.all()
        
        # Get CSCA counts by country and status
        csca_query = (
            select(
                CSCA.country_code,
                CSCA.status,
                func.count(CSCA.id).label('count')
            )
            .group_by(CSCA.country_code, CSCA.status)
        )
        csca_result = await session.execute(csca_query)
        csca_data = csca_result.all()
        
        # Get DSC counts by country and status
        dsc_query = (
            select(
                DSC.country_code,
                DSC.status,
                func.count(DSC.id).label('count')
            )
            .group_by(DSC.country_code, DSC.status)
        )
        dsc_result = await session.execute(dsc_query)
        dsc_data = dsc_result.all()
        
        # Get active sources count
        sources_query = select(func.count(Source.id)).where(Source.is_active == True)
        sources_result = await session.execute(sources_query)
        active_sources_count = sources_result.scalar() or 0
        
        # Calculate data freshness (oldest master list update)
        now = datetime.utcnow()
        oldest_update = None
        if master_lists_data:
            oldest_update = min(row.latest_update for row in master_lists_data)
        
        data_freshness_hours = None
        if oldest_update:
            data_freshness_hours = (now - oldest_update).total_seconds() / 3600
        
        # Aggregate counts for metrics
        total_active_cscas = sum(row.count for row in csca_data if row.status == 'active')
        total_active_dscs = sum(row.count for row in dsc_data if row.status == 'active')
        
        return TrustStatusResponse(
            service_name="trust-svc",
            status="healthy",
            timestamp=now,
            data_freshness_hours=data_freshness_hours,
            total_master_lists=len(master_lists_data),
            total_active_cscas=total_active_cscas,
            total_active_dscs=total_active_dscs,
            active_sources_count=active_sources_count,
            countries_covered=[row.country_code for row in master_lists_data]
        )
        
    except Exception as e:
        logger.error(f"Error getting trust status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve trust status"
        )


@router.get(
    "/trust/snapshot",
    response_model=TrustSnapshotResponse,
    summary="Get current trust snapshot",
    description="Returns an immutable snapshot of the current trust state"
)
async def get_trust_snapshot(
    country_code: Optional[str] = Query(None, description="Filter by country code"),
    include_inactive: bool = Query(False, description="Include inactive certificates"),
    session: AsyncSession = Depends(get_async_session)
) -> TrustSnapshotResponse:
    """Get current trust snapshot with optional filtering."""
    
    try:
        # Build query conditions
        conditions = []
        if country_code:
            conditions.append(CSCA.country_code == country_code.upper())
        if not include_inactive:
            conditions.append(CSCA.status == 'active')
        
        # Get CSCAs with their DSCs
        csca_query = (
            select(CSCA)
            .where(and_(*conditions) if conditions else True)
            .order_by(CSCA.country_code, CSCA.created_at)
        )
        csca_result = await session.execute(csca_query)
        cscas = csca_result.scalars().all()
        
        # Get DSCs for the CSCAs
        snapshot_entries = []
        for csca in cscas:
            dsc_conditions = [DSC.issuer_csca_id == csca.id]
            if not include_inactive:
                dsc_conditions.append(DSC.status == 'active')
            
            dsc_query = (
                select(DSC)
                .where(and_(*dsc_conditions))
                .order_by(DSC.created_at)
            )
            dsc_result = await session.execute(dsc_query)
            dscs = dsc_result.scalars().all()
            
            snapshot_entries.append(TrustSnapshotEntry(
                csca_id=str(csca.id),
                country_code=csca.country_code,
                csca_subject_dn=csca.subject_dn,
                csca_serial_number=csca.serial_number,
                csca_valid_from=csca.valid_from,
                csca_valid_to=csca.valid_to,
                csca_status=csca.status,
                trust_level=csca.trust_level,
                dsc_count=len(dscs),
                dsc_ids=[str(dsc.id) for dsc in dscs]
            ))
        
        return TrustSnapshotResponse(
            snapshot_id=f"snapshot_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            generated_at=datetime.utcnow(),
            country_filter=country_code,
            include_inactive=include_inactive,
            total_cscas=len(snapshot_entries),
            total_dscs=sum(entry.dsc_count for entry in snapshot_entries),
            entries=snapshot_entries
        )
        
    except Exception as e:
        logger.error(f"Error generating trust snapshot: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate trust snapshot"
        )


@router.get(
    "/trust/anchors",
    response_model=TrustAnchorsResponse,
    summary="Get trust anchors (CSCAs)",
    description="Returns list of trusted Certificate Authorities (CSCAs)"
)
async def get_trust_anchors(
    country_code: Optional[str] = Query(None, description="Filter by country code"),
    trust_level: Optional[str] = Query(None, description="Filter by trust level"),
    status_filter: Optional[str] = Query("active", description="Filter by status"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    session: AsyncSession = Depends(get_async_session)
) -> TrustAnchorsResponse:
    """Get trust anchors (CSCAs) with optional filtering and pagination."""
    
    try:
        # Build query conditions
        conditions = []
        if country_code:
            conditions.append(CSCA.country_code == country_code.upper())
        if trust_level:
            conditions.append(CSCA.trust_level == trust_level)
        if status_filter:
            conditions.append(CSCA.status == status_filter)
        
        # Get total count
        count_query = (
            select(func.count(CSCA.id))
            .where(and_(*conditions) if conditions else True)
        )
        count_result = await session.execute(count_query)
        total_count = count_result.scalar() or 0
        
        # Get paginated results
        csca_query = (
            select(CSCA)
            .where(and_(*conditions) if conditions else True)
            .order_by(CSCA.country_code, CSCA.created_at)
            .limit(limit)
            .offset(offset)
        )
        csca_result = await session.execute(csca_query)
        cscas = csca_result.scalars().all()
        
        # Convert to response format
        trust_anchors = []
        for csca in cscas:
            trust_anchors.append(TrustAnchor(
                id=str(csca.id),
                country_code=csca.country_code,
                subject_dn=csca.subject_dn,
                issuer_dn=csca.issuer_dn,
                serial_number=csca.serial_number,
                certificate_hash=csca.certificate_hash,
                valid_from=csca.valid_from,
                valid_to=csca.valid_to,
                trust_level=csca.trust_level,
                status=csca.status,
                key_usage=csca.key_usage or [],
                signature_algorithm=csca.signature_algorithm,
                public_key_algorithm=csca.public_key_algorithm,
                created_at=csca.created_at,
                updated_at=csca.updated_at
            ))
        
        return TrustAnchorsResponse(
            total_count=total_count,
            limit=limit,
            offset=offset,
            country_filter=country_code,
            trust_level_filter=trust_level,
            status_filter=status_filter,
            anchors=trust_anchors
        )
        
    except Exception as e:
        logger.error(f"Error getting trust anchors: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve trust anchors"
        )