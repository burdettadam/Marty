"""gRPC server implementation for Trust Service."""

import asyncio
import logging
from concurrent import futures
from datetime import datetime, timezone
from typing import AsyncGenerator, List, Optional

import grpc
from grpc import aio
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .certificate_service import TrustServiceCertificateValidator
from .database import get_async_session
from .models import CSCA, DSC, MasterList, CRL, Source, CertificateStatus, TrustLevel, SourceType
from .metrics import record_grpc_request, update_service_health
from .config import settings

# Import generated gRPC files (will be available after proto compilation)
try:
    from .grpc_generated import trust_service_pb2, trust_service_pb2_grpc
except ImportError:
    # Placeholder for when proto files aren't compiled yet
    trust_service_pb2 = None
    trust_service_pb2_grpc = None

logger = logging.getLogger(__name__)


class TrustServiceGRPC(trust_service_pb2_grpc.TrustServiceServicer if trust_service_pb2_grpc else object):
    """gRPC service implementation for Trust Service."""
    
    def __init__(self):
        """Initialize the gRPC service."""
        self.start_time = datetime.now(timezone.utc)
        self.certificate_validator = TrustServiceCertificateValidator()
    
    async def GetTrustStatus(self, request, context):
        """Get service status and health information."""
        start_time = datetime.now(timezone.utc)
        
        try:
            async for session in get_async_session():
                # Get master list counts
                ml_query = select(func.count(MasterList.id))
                if request.country_code:
                    ml_query = ml_query.where(MasterList.country_code == request.country_code.upper())
                
                ml_result = await session.execute(ml_query)
                total_master_lists = ml_result.scalar() or 0
                
                # Get CSCA counts
                csca_query = select(func.count(CSCA.id)).where(CSCA.status == CertificateStatus.ACTIVE)
                if request.country_code:
                    csca_query = csca_query.where(CSCA.country_code == request.country_code.upper())
                
                csca_result = await session.execute(csca_query)
                total_active_cscas = csca_result.scalar() or 0
                
                # Get DSC counts
                dsc_query = select(func.count(DSC.id)).where(DSC.status == CertificateStatus.ACTIVE)
                if request.country_code:
                    dsc_query = dsc_query.where(DSC.country_code == request.country_code.upper())
                
                dsc_result = await session.execute(dsc_query)
                total_active_dscs = dsc_result.scalar() or 0
                
                # Get active sources count
                sources_query = select(func.count(Source.id)).where(Source.is_active == True)
                sources_result = await session.execute(sources_query)
                active_sources_count = sources_result.scalar() or 0
                
                # Get countries covered
                countries_query = select(MasterList.country_code).distinct()
                countries_result = await session.execute(countries_query)
                countries_covered = [row[0] for row in countries_result.all()]
                
                # Calculate data freshness
                freshness_query = select(func.max(MasterList.updated_at))
                freshness_result = await session.execute(freshness_query)
                latest_update = freshness_result.scalar()
                
                data_freshness_hours = None
                if latest_update:
                    now = datetime.now(timezone.utc)
                    data_freshness_hours = (now - latest_update).total_seconds() / 3600
                
                # Component health checks
                component_health = [
                    trust_service_pb2.ComponentHealth(
                        component="database",
                        is_healthy=True,
                        last_check=trust_service_pb2.google.protobuf.timestamp.Timestamp()
                    ),
                    trust_service_pb2.ComponentHealth(
                        component="pkd_sync",
                        is_healthy=True,
                        last_check=trust_service_pb2.google.protobuf.timestamp.Timestamp()
                    )
                ]
                
                # Record metrics
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                record_grpc_request("GetTrustStatus", "OK", duration)
                
                return trust_service_pb2.TrustStatusResponse(
                    service_name="trust-svc",
                    status="healthy",
                    timestamp=trust_service_pb2.google.protobuf.timestamp.Timestamp(),
                    data_freshness_hours=data_freshness_hours,
                    total_master_lists=total_master_lists,
                    total_active_cscas=total_active_cscas,
                    total_active_dscs=total_active_dscs,
                    active_sources_count=active_sources_count,
                    countries_covered=countries_covered,
                    component_health=component_health
                )
                
        except Exception as e:
            logger.error(f"Error in GetTrustStatus: {e}")
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            record_grpc_request("GetTrustStatus", "ERROR", duration)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {str(e)}")
            return trust_service_pb2.TrustStatusResponse()
    
    async def GetTrustAnchors(self, request, context):
        """Get trust anchors (CSCAs) with filtering."""
        start_time = datetime.now(timezone.utc)
        
        try:
            async for session in get_async_session():
                # Build query conditions
                conditions = []
                if request.country_code:
                    conditions.append(CSCA.country_code == request.country_code.upper())
                if request.trust_level and request.trust_level != trust_service_pb2.TRUST_LEVEL_UNSPECIFIED:
                    trust_level_map = {
                        trust_service_pb2.TRUST_LEVEL_STANDARD: TrustLevel.STANDARD,
                        trust_service_pb2.TRUST_LEVEL_HIGH: TrustLevel.HIGH,
                        trust_service_pb2.TRUST_LEVEL_EMERGENCY: TrustLevel.EMERGENCY
                    }
                    conditions.append(CSCA.trust_level == trust_level_map[request.trust_level])
                if request.status and request.status != trust_service_pb2.CERTIFICATE_STATUS_UNSPECIFIED:
                    status_map = {
                        trust_service_pb2.CERTIFICATE_STATUS_ACTIVE: CertificateStatus.ACTIVE,
                        trust_service_pb2.CERTIFICATE_STATUS_INACTIVE: CertificateStatus.INACTIVE,
                        trust_service_pb2.CERTIFICATE_STATUS_REVOKED: CertificateStatus.REVOKED
                    }
                    conditions.append(CSCA.status == status_map[request.status])
                
                # Get total count
                count_query = select(func.count(CSCA.id))
                if conditions:
                    count_query = count_query.where(and_(*conditions))
                
                count_result = await session.execute(count_query)
                total_count = count_result.scalar() or 0
                
                # Get paginated results
                page_size = min(request.page_size or 100, 1000)
                offset = 0  # Implement proper pagination with page_token
                
                csca_query = select(CSCA)
                if conditions:
                    csca_query = csca_query.where(and_(*conditions))
                csca_query = csca_query.order_by(CSCA.country_code, CSCA.created_at).limit(page_size).offset(offset)
                
                csca_result = await session.execute(csca_query)
                cscas = csca_result.scalars().all()
                
                # Convert to protobuf messages
                anchors = []
                for csca in cscas:
                    trust_level_map = {
                        TrustLevel.STANDARD: trust_service_pb2.TRUST_LEVEL_STANDARD,
                        TrustLevel.HIGH: trust_service_pb2.TRUST_LEVEL_HIGH,
                        TrustLevel.EMERGENCY: trust_service_pb2.TRUST_LEVEL_EMERGENCY
                    }
                    
                    status_map = {
                        CertificateStatus.ACTIVE: trust_service_pb2.CERTIFICATE_STATUS_ACTIVE,
                        CertificateStatus.INACTIVE: trust_service_pb2.CERTIFICATE_STATUS_INACTIVE,
                        CertificateStatus.REVOKED: trust_service_pb2.CERTIFICATE_STATUS_REVOKED
                    }
                    
                    anchor = trust_service_pb2.TrustAnchor(
                        id=str(csca.id),
                        country_code=csca.country_code,
                        subject_dn=csca.subject_dn,
                        issuer_dn=csca.issuer_dn,
                        serial_number=csca.serial_number,
                        certificate_hash=csca.certificate_hash,
                        trust_level=trust_level_map.get(csca.trust_level, trust_service_pb2.TRUST_LEVEL_STANDARD),
                        status=status_map.get(csca.status, trust_service_pb2.CERTIFICATE_STATUS_ACTIVE),
                        key_usage=csca.key_usage or [],
                        signature_algorithm=csca.signature_algorithm or "",
                        public_key_algorithm=csca.public_key_algorithm or ""
                    )
                    
                    # Set timestamps
                    anchor.valid_from.FromDatetime(csca.valid_from)
                    anchor.valid_to.FromDatetime(csca.valid_to)
                    anchor.created_at.FromDatetime(csca.created_at)
                    anchor.updated_at.FromDatetime(csca.updated_at)
                    
                    # Include certificate data if requested
                    if hasattr(request, 'include_certificate_data') and request.include_certificate_data:
                        anchor.certificate_data = csca.certificate_data
                    
                    anchors.append(anchor)
                
                # Record metrics
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                record_grpc_request("GetTrustAnchors", "OK", duration)
                
                return trust_service_pb2.GetTrustAnchorsResponse(
                    anchors=anchors,
                    total_count=total_count,
                    next_page_token=""  # Implement proper pagination
                )
                
        except Exception as e:
            logger.error(f"Error in GetTrustAnchors: {e}")
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            record_grpc_request("GetTrustAnchors", "ERROR", duration)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {str(e)}")
            return trust_service_pb2.GetTrustAnchorsResponse()
    
    async def GetTrustSnapshot(self, request, context):
        """Get trust snapshot."""
        start_time = datetime.now(timezone.utc)
        
        try:
            async for session in get_async_session():
                # Build conditions
                conditions = []
                if request.country_code:
                    conditions.append(CSCA.country_code == request.country_code.upper())
                if not request.include_inactive:
                    conditions.append(CSCA.status == CertificateStatus.ACTIVE)
                
                # Get CSCAs
                csca_query = select(CSCA)
                if conditions:
                    csca_query = csca_query.where(and_(*conditions))
                csca_query = csca_query.order_by(CSCA.country_code, CSCA.created_at)
                
                csca_result = await session.execute(csca_query)
                cscas = csca_result.scalars().all()
                
                # Build snapshot entries
                entries = []
                total_dscs = 0
                
                for csca in cscas:
                    # Get DSCs for this CSCA
                    dsc_conditions = [DSC.issuer_csca_id == csca.id]
                    if not request.include_inactive:
                        dsc_conditions.append(DSC.status == CertificateStatus.ACTIVE)
                    
                    dsc_query = select(DSC).where(and_(*dsc_conditions))
                    dsc_result = await session.execute(dsc_query)
                    dscs = dsc_result.scalars().all()
                    
                    total_dscs += len(dscs)
                    
                    entry = trust_service_pb2.TrustSnapshotEntry(
                        csca_id=str(csca.id),
                        country_code=csca.country_code,
                        csca_subject_dn=csca.subject_dn,
                        csca_serial_number=csca.serial_number,
                        csca_status=trust_service_pb2.CERTIFICATE_STATUS_ACTIVE,  # Map from enum
                        trust_level=trust_service_pb2.TRUST_LEVEL_STANDARD,      # Map from enum
                        dsc_count=len(dscs),
                        dsc_ids=[str(dsc.id) for dsc in dscs]
                    )
                    
                    # Set timestamps
                    entry.csca_valid_from.FromDatetime(csca.valid_from)
                    entry.csca_valid_to.FromDatetime(csca.valid_to)
                    
                    # Include certificate data if requested
                    if request.include_certificate_data:
                        entry.csca_certificate_data = csca.certificate_data
                    
                    entries.append(entry)
                
                # Generate snapshot
                now = datetime.now(timezone.utc)
                snapshot_id = f"snapshot_{now.strftime('%Y%m%d_%H%M%S')}"
                
                response = trust_service_pb2.GetTrustSnapshotResponse(
                    snapshot_id=snapshot_id,
                    country_filter=request.country_code or "",
                    include_inactive=request.include_inactive,
                    total_cscas=len(entries),
                    total_dscs=total_dscs,
                    entries=entries,
                    checksum="",  # Implement checksum calculation
                )
                
                response.generated_at.FromDatetime(now)
                
                # Record metrics
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                record_grpc_request("GetTrustSnapshot", "OK", duration)
                
                return response
                
        except Exception as e:
            logger.error(f"Error in GetTrustSnapshot: {e}")
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            record_grpc_request("GetTrustSnapshot", "ERROR", duration)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {str(e)}")
            return trust_service_pb2.GetTrustSnapshotResponse()
    
    async def ValidateCertificate(self, request, context):
        """Validate certificate chain using advanced X.509 parsing."""
        start_time = datetime.now(timezone.utc)
        
        try:
            # Get certificate data from request
            if not request.certificate_data:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("Certificate data is required")
                return trust_service_pb2.ValidateCertificateResponse()
            
            # Validate certificate using the certificate service
            async for session in get_async_session():
                validation_result = await self.certificate_validator.validate_certificate_data(
                    cert_data=request.certificate_data,
                    country_code=request.country_code if request.country_code else None,
                    session=session
                )
                
                # Check if chain validation is requested
                if hasattr(request, 'certificate_chain') and request.certificate_chain:
                    chain_validation = await self.certificate_validator.validate_certificate_chain(
                        cert_chain=[request.certificate_data] + list(request.certificate_chain),
                        session=session
                    )
                    validation_result["chain_validation"] = chain_validation
                
                # Map validation results to protobuf response
                is_valid = validation_result.get("is_valid", False)
                revocation_status = validation_result.get("revocation_status", "unknown")
                
                # Map revocation status to protobuf enum
                revocation_status_map = {
                    "not_revoked": trust_service_pb2.REVOCATION_STATUS_NOT_REVOKED,
                    "revoked": trust_service_pb2.REVOCATION_STATUS_REVOKED,
                    "unknown": trust_service_pb2.REVOCATION_STATUS_UNKNOWN
                }
                
                # Create trust path from validation results
                trust_path = []
                if "trust_path" in validation_result:
                    for cert in validation_result["trust_path"]:
                        path_cert = trust_service_pb2.CertificateInfo(
                            subject_dn=cert.get("subject", ""),
                            fingerprint_sha256=cert.get("fingerprint", "")
                        )
                        trust_path.append(path_cert)
                
                # Create validation errors list
                validation_errors = validation_result.get("errors", [])
                
                # Record metrics
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                result_label = "valid" if is_valid else "invalid"
                record_grpc_request("ValidateCertificate", result_label.upper(), duration)
                
                response = trust_service_pb2.ValidateCertificateResponse(
                    is_valid=is_valid,
                    revocation_status=revocation_status_map.get(revocation_status, trust_service_pb2.REVOCATION_STATUS_UNKNOWN),
                    trust_path=trust_path,
                    validation_errors=validation_errors
                )
                
                # Set validation timestamp
                response.validation_time.FromDatetime(datetime.now(timezone.utc))
                
                # Add certificate details if available
                if "certificate_info" in validation_result:
                    cert_info = validation_result["certificate_info"]
                    response.certificate_subject = cert_info.get("subject", "")
                    response.certificate_issuer = cert_info.get("issuer", "")
                    response.certificate_serial = cert_info.get("serial_number", "")
                    response.country_code = cert_info.get("country_code", "")
                
                return response
                
        except Exception as e:
            logger.error(f"Error in ValidateCertificate: {e}")
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            record_grpc_request("ValidateCertificate", "ERROR", duration)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Certificate validation error: {str(e)}")
            return trust_service_pb2.ValidateCertificateResponse()
    
    async def CheckRevocationStatus(self, request, context):
        """Check certificate revocation status."""
        start_time = datetime.now(timezone.utc)
        
        try:
            # Placeholder for revocation checking logic
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            record_grpc_request("CheckRevocationStatus", "OK", duration)
            
            return trust_service_pb2.CheckRevocationStatusResponse(
                status=trust_service_pb2.REVOCATION_STATUS_UNKNOWN
            )
            
        except Exception as e:
            logger.error(f"Error in CheckRevocationStatus: {e}")
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            record_grpc_request("CheckRevocationStatus", "ERROR", duration)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {str(e)}")
            return trust_service_pb2.CheckRevocationStatusResponse()
    
    async def StreamPKDUpdates(self, request, context):
        """Stream PKD data updates."""
        try:
            # Placeholder for streaming implementation
            # This would implement real-time streaming of PKD updates
            
            while True:
                # Send heartbeat or real updates
                if request.include_heartbeat:
                    event = trust_service_pb2.PKDUpdateEvent(
                        event_id=f"heartbeat_{datetime.now(timezone.utc).isoformat()}",
                        event_type=trust_service_pb2.PKD_EVENT_TYPE_HEARTBEAT,
                        source_type=trust_service_pb2.SOURCE_TYPE_ICAO_PKD
                    )
                    event.timestamp.FromDatetime(datetime.now(timezone.utc))
                    yield event
                
                await asyncio.sleep(30)  # Heartbeat every 30 seconds
                
        except Exception as e:
            logger.error(f"Error in StreamPKDUpdates: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Stream error: {str(e)}")
    
    async def RefreshPKDData(self, request, context):
        """Refresh PKD data from sources."""
        start_time = datetime.now(timezone.utc)
        
        try:
            # Placeholder for PKD refresh logic
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            record_grpc_request("RefreshPKDData", "OK", duration)
            
            return trust_service_pb2.RefreshPKDDataResponse(
                job_id=f"refresh_{datetime.now(timezone.utc).isoformat()}",
                status=trust_service_pb2.REFRESH_JOB_STATUS_PENDING
            )
            
        except Exception as e:
            logger.error(f"Error in RefreshPKDData: {e}")
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            record_grpc_request("RefreshPKDData", "ERROR", duration)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {str(e)}")
            return trust_service_pb2.RefreshPKDDataResponse()
    
    async def GetDataSources(self, request, context):
        """Get data sources information."""
        start_time = datetime.now(timezone.utc)
        
        try:
            async for session in get_async_session():
                # Build query
                query = select(Source)
                conditions = []
                
                if request.country_code:
                    conditions.append(Source.country_code == request.country_code.upper())
                if request.source_type and request.source_type != trust_service_pb2.SOURCE_TYPE_UNSPECIFIED:
                    source_type_map = {
                        trust_service_pb2.SOURCE_TYPE_ICAO_PKD: SourceType.ICAO_PKD,
                        trust_service_pb2.SOURCE_TYPE_NATIONAL_PKI: SourceType.NATIONAL_PKI,
                        trust_service_pb2.SOURCE_TYPE_MANUAL: SourceType.MANUAL
                    }
                    conditions.append(Source.source_type == source_type_map[request.source_type])
                if request.active_only:
                    conditions.append(Source.is_active == True)
                
                if conditions:
                    query = query.where(and_(*conditions))
                
                result = await session.execute(query)
                sources = result.scalars().all()
                
                # Convert to protobuf messages
                pb_sources = []
                for source in sources:
                    source_type_map = {
                        SourceType.ICAO_PKD: trust_service_pb2.SOURCE_TYPE_ICAO_PKD,
                        SourceType.NATIONAL_PKI: trust_service_pb2.SOURCE_TYPE_NATIONAL_PKI,
                        SourceType.MANUAL: trust_service_pb2.SOURCE_TYPE_MANUAL
                    }
                    
                    pb_source = trust_service_pb2.DataSource(
                        id=str(source.id),
                        name=source.name,
                        source_type=source_type_map.get(source.source_type, trust_service_pb2.SOURCE_TYPE_UNSPECIFIED),
                        country_code=source.country_code or "",
                        url=source.url,
                        sync_interval=source.sync_interval,
                        last_error=source.last_error or "",
                        is_active=source.is_active,
                        retry_count=source.retry_count
                    )
                    
                    # Set timestamps
                    if source.last_sync:
                        pb_source.last_sync.FromDatetime(source.last_sync)
                    if source.last_success:
                        pb_source.last_success.FromDatetime(source.last_success)
                    pb_source.created_at.FromDatetime(source.created_at)
                    pb_source.updated_at.FromDatetime(source.updated_at)
                    
                    pb_sources.append(pb_source)
                
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                record_grpc_request("GetDataSources", "OK", duration)
                
                return trust_service_pb2.GetDataSourcesResponse(sources=pb_sources)
                
        except Exception as e:
            logger.error(f"Error in GetDataSources: {e}")
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            record_grpc_request("GetDataSources", "ERROR", duration)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {str(e)}")
            return trust_service_pb2.GetDataSourcesResponse()


async def serve_grpc():
    """Start the gRPC server."""
    if not trust_service_pb2_grpc:
        logger.error("gRPC proto files not compiled. Run 'python compile_protos.py' first.")
        return
    
    # Create server
    server = aio.server(futures.ThreadPoolExecutor(max_workers=settings.grpc_max_workers))
    
    # Add service
    trust_service_pb2_grpc.add_TrustServiceServicer_to_server(TrustServiceGRPC(), server)
    
    # Configure server
    listen_addr = f"[::]:{settings.grpc_port}"
    server.add_insecure_port(listen_addr)
    
    # Start server
    logger.info(f"Starting gRPC server on {listen_addr}")
    await server.start()
    
    # Update health metrics
    update_service_health("grpc", True)
    
    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down gRPC server...")
        await server.stop(grace=5.0)
        update_service_health("grpc", False)


if __name__ == "__main__":
    asyncio.run(serve_grpc())