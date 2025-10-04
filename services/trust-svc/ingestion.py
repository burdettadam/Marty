"""PKD and HML data ingestion services."""

import asyncio
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .certificate_parser import CertificateType
from .certificate_service import TrustServiceCertificateValidator
from .config import settings
from .database import get_async_session
from .models import Source, MasterList, CSCA, DSC, CRL, Provenance, SourceType
from .metrics import (
    record_pkd_sync, update_master_list_age, 
    update_trusted_csca_count, update_trusted_dsc_count
)

logger = logging.getLogger(__name__)


class PKDIngestionService:
    """Service for ingesting PKD (Public Key Directory) data."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.certificate_validator = TrustServiceCertificateValidator()
        self.http_session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.database_timeout)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.http_session:
            await self.http_session.close()
    
    async def sync_all_sources(self) -> Dict[str, List[str]]:
        """Sync data from all active PKD sources."""
        results = {"success": [], "failed": []}
        
        # Get all active sources
        sources_query = select(Source).where(Source.is_active == True)
        sources_result = await self.session.execute(sources_query)
        sources = sources_result.scalars().all()
        
        logger.info(f"Starting sync for {len(sources)} active sources")
        
        for source in sources:
            try:
                start_time = datetime.now(timezone.utc)
                await self._sync_source(source)
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                
                # Update source last success
                source.last_success = start_time
                source.retry_count = 0
                source.last_error = None
                
                results["success"].append(source.name)
                record_pkd_sync(source.source_type, source.country_code or "global", "success", duration)
                
                logger.info(f"Successfully synced source: {source.name}")
                
            except Exception as e:
                # Update source error info
                source.last_error = str(e)
                source.retry_count += 1
                
                results["failed"].append(f"{source.name}: {str(e)}")
                record_pkd_sync(source.source_type, source.country_code or "global", "failed")
                
                logger.error(f"Failed to sync source {source.name}: {e}")
        
        await self.session.commit()
        return results
    
    async def _sync_source(self, source: Source) -> None:
        """Sync data from a single PKD source."""
        source.last_sync = datetime.now(timezone.utc)
        
        if source.source_type == SourceType.ICAO_PKD:
            await self._sync_icao_pkd(source)
        elif source.source_type == SourceType.NATIONAL_PKI:
            await self._sync_national_pki(source)
        else:
            logger.warning(f"Unknown source type: {source.source_type}")
    
    async def _sync_icao_pkd(self, source: Source) -> None:
        """Sync data from ICAO PKD source."""
        if not self.http_session:
            raise RuntimeError("HTTP session not initialized")
        
        # Authentication setup
        auth = None
        if source.credentials:
            username = source.credentials.get("username")
            password = source.credentials.get("password")
            if username and password:
                auth = aiohttp.BasicAuth(username, password)
        
        try:
            # Fetch master list data
            async with self.http_session.get(source.url, auth=auth) as response:
                response.raise_for_status()
                data = await response.read()
                
                # Parse and store master list
                await self._process_master_list_data(source, data)
                
        except aiohttp.ClientError as e:
            raise Exception(f"HTTP error fetching from {source.url}: {e}")
    
    async def _sync_national_pki(self, source: Source) -> None:
        """Sync data from national PKI source."""
        # Placeholder for national PKI sync logic
        logger.info(f"Syncing national PKI source: {source.name}")
        # Implementation would depend on the specific national PKI format
    
    async def _process_master_list_data(self, source: Source, data: bytes) -> None:
        """Process and store master list data."""
        content_hash = hashlib.sha256(data).hexdigest()
        
        # Check if we already have this version
        existing_query = select(MasterList).where(
            MasterList.content_hash == content_hash,
            MasterList.country_code == source.country_code
        )
        existing_result = await self.session.execute(existing_query)
        existing_ml = existing_result.scalar_one_or_none()
        
        if existing_ml:
            logger.info(f"Master list {content_hash} already exists, skipping")
            return
        
        # Parse the data (this would need proper ASN.1/X.509 parsing)
        try:
            certificates = await self._parse_master_list_certificates(data)
            
            # Create new master list entry
            master_list = MasterList(
                country_code=source.country_code or "UNK",
                version=1,  # This should be extracted from the data
                source_type=source.source_type,
                source_url=source.url,
                content_hash=content_hash,
                content_data=data,
                valid_from=datetime.now(timezone.utc),
                valid_to=datetime.now(timezone.utc).replace(year=datetime.now().year + 1),
                issued_by=source.name,
                metadata={"source_id": str(source.id)}
            )
            
            self.session.add(master_list)
            await self.session.flush()  # Get the ID
            
            # Process certificates
            await self._process_certificates(master_list, certificates)
            
            # Create provenance record
            provenance = Provenance(
                entity_type="master_list",
                entity_id=master_list.id,
                source_id=source.id,
                operation="create",
                checksum=content_hash,
                metadata={"certificate_count": len(certificates)}
            )
            self.session.add(provenance)
            
            logger.info(f"Processed master list with {len(certificates)} certificates")
            
        except Exception as e:
            raise Exception(f"Failed to process master list data: {e}")
    
    async def _parse_master_list_certificates(self, data: bytes) -> List[Dict]:
        """Parse certificates from master list data using advanced certificate parser."""
        certificates = []
        
        try:
            # This is a simplified approach - real ICAO master list parsing would be more complex
            # For now, assume the data contains individual certificate blocks
            
            # Try to extract PEM blocks or DER certificates from the data
            cert_blocks = self._extract_certificate_blocks(data)
            
            for cert_block in cert_blocks:
                try:
                    # Use the certificate validator to parse and validate
                    validation_result = await self.certificate_validator.validate_certificate_data(
                        cert_block, session=self.session
                    )
                    
                    if validation_result["certificate_info"]:
                        cert_info = validation_result["certificate_info"]
                        
                        # Determine certificate type
                        cert_type = CertificateType.CSCA if cert_info["is_ca"] else CertificateType.DSC
                        
                        certificates.append({
                            "data": cert_block,
                            "type": cert_type,
                            "info": cert_info,
                            "validation": validation_result
                        })
                        
                except Exception as e:
                    logger.warning(f"Failed to parse certificate block: {e}")
                    continue
            
            logger.info(f"Successfully parsed {len(certificates)} certificates from master list")
            
        except Exception as e:
            logger.error(f"Error parsing master list certificates: {e}")
        
        return certificates
    
    def _extract_certificate_blocks(self, data: bytes) -> List[bytes]:
        """Extract individual certificate blocks from master list data."""
        cert_blocks = []
        
        try:
            # Look for PEM blocks
            data_str = data.decode('utf-8', errors='ignore')
            
            # Extract PEM certificates
            import re
            pem_pattern = r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----'
            pem_matches = re.findall(pem_pattern, data_str, re.DOTALL)
            
            for pem_cert in pem_matches:
                cert_blocks.append(pem_cert.encode())
            
            # If no PEM found, try to extract DER certificates
            if not cert_blocks:
                # This would need more sophisticated ASN.1 parsing to properly
                # extract DER certificates from a master list structure
                # For now, assume the entire data is one certificate
                if len(data) > 100:  # Reasonable minimum size for a certificate
                    cert_blocks.append(data)
            
        except Exception as e:
            logger.error(f"Error extracting certificate blocks: {e}")
        
        return cert_blocks
    
    async def _process_certificates(self, master_list: MasterList, certificates: List[Dict]) -> None:
        """Process and store certificates from master list using certificate parser."""
        for cert_entry in certificates:
            try:
                cert_data = cert_entry["data"]
                cert_type = cert_entry["type"]
                cert_info = cert_entry["info"]
                
                # Store certificate using the certificate service
                cert_id = await self.certificate_validator.parse_and_store_certificate(
                    cert_data=cert_data,
                    certificate_type=cert_type,
                    source_id=str(master_list.source_id),
                    session=self.session
                )
                
                if cert_id:
                    # Create provenance record
                    provenance = Provenance(
                        object_type="certificate",
                        object_id=cert_id,
                        source_id=master_list.source_id,
                        master_list_id=master_list.id,
                        operation="import",
                        metadata={
                            "certificate_type": cert_type.value,
                            "country_code": cert_info.get("country_code"),
                            "fingerprint": cert_info.get("fingerprint_sha256"),
                            "validation_result": cert_entry["validation"]["is_valid"]
                        }
                    )
                    self.session.add(provenance)
                    
                    logger.info(f"Stored {cert_type.value} certificate: {cert_info.get('subject', 'Unknown')}")
                else:
                    logger.warning(f"Failed to store certificate or already exists")
                    
            except Exception as e:
                logger.error(f"Error processing certificate: {e}")
                continue
    
    async def _store_dsc(self, master_list: MasterList, cert_data: Dict) -> None:
        """Store DSC certificate."""
        cert_hash = cert_data.get("hash", "")
        
        # Check if already exists
        existing_query = select(DSC).where(DSC.certificate_hash == cert_hash)
        existing_result = await self.session.execute(existing_query)
        existing_dsc = existing_result.scalar_one_or_none()
        
        if existing_dsc:
            return
        
        dsc = DSC(
            country_code=master_list.country_code,
            certificate_hash=cert_hash,
            certificate_data=cert_data.get("data", b""),
            subject_dn=cert_data.get("subject_dn", ""),
            issuer_dn=cert_data.get("issuer_dn", ""),
            serial_number=cert_data.get("serial_number", ""),
            valid_from=cert_data.get("valid_from", datetime.now(timezone.utc)),
            valid_to=cert_data.get("valid_to", datetime.now(timezone.utc)),
            key_usage=cert_data.get("key_usage", []),
            signature_algorithm=cert_data.get("signature_algorithm"),
            public_key_algorithm=cert_data.get("public_key_algorithm"),
            master_list_id=master_list.id
        )
        
        self.session.add(dsc)


class HMLIngestionService:
    """Service for ingesting HML (Hash Master List) data."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def sync_hml_data(self) -> Dict[str, int]:
        """Sync HML data from configured sources."""
        # Placeholder for HML ingestion logic
        return {"processed": 0, "updated": 0, "errors": 0}


async def run_periodic_sync():
    """Run periodic PKD/HML synchronization."""
    logger.info("Starting periodic PKD/HML sync")
    
    try:
        async for session in get_async_session():
            async with PKDIngestionService(session) as pkd_service:
                results = await pkd_service.sync_all_sources()
                
                logger.info(f"Sync completed - Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
                if results["failed"]:
                    logger.warning(f"Failed sources: {results['failed']}")
    
    except Exception as e:
        logger.error(f"Error in periodic sync: {e}")
    
    # Schedule next sync
    await asyncio.sleep(settings.pkd_sync_interval)