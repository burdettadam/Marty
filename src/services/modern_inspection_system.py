"""
Modern Inspection System Service with Unified Observability
Handles document verification, passport validation, SD-JWT verification, and OID4VP presentations
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import grpc
from grpc import aio
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

# Import unified framework components
from src.utils.observability import (
    ObservabilityManager,
    MartyMetrics,
    trace_function,
    correlation_context,
    BusinessMetricsTracker,
    SecurityEventLogger
)
from src.utils.grpc_server import UnifiedGrpcServer
from src.utils.database import DatabaseManager
from src.utils.object_storage import ObjectStorageManager
from src.utils.key_vault import KeyVaultManager

# Import service-specific components
from src.proto import inspection_system_pb2, inspection_system_pb2_grpc
from src.services.trust_anchor import TrustAnchorClient
from src.services.document_signer import DocumentSignerClient
from src.utils.config import Config
from src.utils.exceptions import (
    InspectionError,
    VerificationError,
    TrustValidationError,
    ComplianceError
)

logger = logging.getLogger(__name__)


class InspectionSystemService(inspection_system_pb2_grpc.InspectionSystemServicer):
    """Modern Inspection System with comprehensive verification capabilities"""
    
    def __init__(self, config: Config):
        self.config = config
        self.service_name = "inspection-system"
        
        # Initialize unified observability
        self.observability = ObservabilityManager(
            service_name=self.service_name,
            config=config
        )
        self.metrics = MartyMetrics(config)
        self.business_metrics = BusinessMetricsTracker(config)
        self.security_logger = SecurityEventLogger(config)
        
        # Initialize storage and external services
        self.db_manager = DatabaseManager(config)
        self.storage_manager = ObjectStorageManager(config)
        self.key_vault = KeyVaultManager(config)
        
        # Initialize client connections
        self.trust_anchor_client = None
        self.document_signer_client = None
        
        # Verification configuration
        self.inspection_config = config.get('inspection_system', {})
        self.verification_config = self.inspection_config.get('verification', {})
        
        # Data directories
        self.data_dir = Path(self.inspection_config.get('data_dir', '/app/data'))
        self.passport_data_dir = Path(self.inspection_config.get('passport_data_dir', '/app/passport_data'))
        self.config_dir = Path(self.inspection_config.get('config_dir', '/app/config'))
        
        # Cache for trust anchors and presentation definitions
        self._trust_anchor_cache = {}
        self._presentation_definition_cache = {}
        self._cache_ttl = self.inspection_config.get('performance', {}).get('cache_ttl', 3600)
        
        logger.info(f"Initialized {self.service_name} with observability framework")
    
    async def initialize(self):
        """Initialize service dependencies"""
        try:
            # Initialize database
            await self.db_manager.initialize()
            
            # Initialize object storage
            await self.storage_manager.initialize()
            
            # Initialize key vault
            await self.key_vault.initialize()
            
            # Initialize external service clients
            await self._initialize_service_clients()
            
            # Start health checks
            await self.observability.start_health_checks()
            
            logger.info("Inspection System service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Inspection System service: {e}")
            raise
    
    async def _initialize_service_clients(self):
        """Initialize external service clients"""
        try:
            # Initialize Trust Anchor client
            trust_anchor_host = self.config.get('service_discovery', {}).get('hosts', {}).get('trust_anchor')
            trust_anchor_port = self.config.get('service_discovery', {}).get('ports', {}).get('trust_anchor')
            
            if trust_anchor_host and trust_anchor_port:
                self.trust_anchor_client = TrustAnchorClient(
                    host=trust_anchor_host,
                    port=trust_anchor_port
                )
                await self.trust_anchor_client.initialize()
            
            # Initialize Document Signer client
            doc_signer_host = self.config.get('service_discovery', {}).get('hosts', {}).get('document_signer')
            doc_signer_port = self.config.get('service_discovery', {}).get('ports', {}).get('document_signer')
            
            if doc_signer_host and doc_signer_port:
                self.document_signer_client = DocumentSignerClient(
                    host=doc_signer_host,
                    port=doc_signer_port
                )
                await self.document_signer_client.initialize()
                
        except Exception as e:
            logger.error(f"Failed to initialize service clients: {e}")
            raise
    
    @trace_function("inspection_system.inspect_document")
    async def Inspect(self, request: inspection_system_pb2.InspectRequest, context) -> inspection_system_pb2.InspectResponse:
        """Perform comprehensive document inspection"""
        start_time = time.time()
        
        with correlation_context():
            try:
                # Extract correlation ID
                correlation_id = context.get_trailing_metadata().get('x-correlation-id', 'unknown')
                
                # Track operation metrics
                self.metrics.increment_counter(
                    'inspection_operations_total',
                    {
                        'operation': 'inspect',
                        'document_type': request.document_type,
                        'verification_type': request.verification_type
                    }
                )
                
                logger.info(f"Starting document inspection: type={request.document_type}, "
                           f"verification={request.verification_type}, correlation_id={correlation_id}")
                
                # Validate request
                await self._validate_inspection_request(request)
                
                # Perform inspection based on document type
                inspection_result = await self._perform_inspection(request, correlation_id)
                
                # Create response
                response = inspection_system_pb2.InspectResponse(
                    correlation_id=correlation_id,
                    inspection_id=inspection_result['inspection_id'],
                    verification_result=inspection_result['verification_result'],
                    confidence_score=inspection_result['confidence_score'],
                    validation_details=json.dumps(inspection_result['validation_details']),
                    security_features=inspection_result.get('security_features', []),
                    compliance_status=inspection_result['compliance_status'],
                    timestamp=int(time.time())
                )
                
                # Track success metrics
                processing_time = time.time() - start_time
                self._track_inspection_success(request, inspection_result, processing_time)
                
                logger.info(f"Document inspection completed successfully: "
                           f"inspection_id={inspection_result['inspection_id']}, "
                           f"confidence={inspection_result['confidence_score']:.2f}")
                
                return response
                
            except Exception as e:
                # Track failure metrics
                processing_time = time.time() - start_time
                self._track_inspection_failure(request, e, processing_time)
                
                logger.error(f"Document inspection failed: {e}")
                
                # Return error response
                return inspection_system_pb2.InspectResponse(
                    correlation_id=correlation_id if 'correlation_id' in locals() else 'error',
                    verification_result=inspection_system_pb2.VerificationResult.FAILED,
                    error_message=str(e),
                    timestamp=int(time.time())
                )
    
    @trace_function("inspection_system.verify_presentation")
    async def VerifyPresentation(self, request: inspection_system_pb2.VerifyPresentationRequest, context) -> inspection_system_pb2.VerifyPresentationResponse:
        """Verify OID4VP presentation"""
        start_time = time.time()
        
        with correlation_context():
            try:
                correlation_id = context.get_trailing_metadata().get('x-correlation-id', 'unknown')
                
                # Track operation metrics
                self.metrics.increment_counter(
                    'oid4vp_presentation_total',
                    {
                        'presentation_type': request.presentation_type,
                        'validation_step': 'start'
                    }
                )
                
                logger.info(f"Starting OID4VP presentation verification: "
                           f"type={request.presentation_type}, correlation_id={correlation_id}")
                
                # Perform presentation verification
                verification_result = await self._verify_oid4vp_presentation(request, correlation_id)
                
                # Create response
                response = inspection_system_pb2.VerifyPresentationResponse(
                    correlation_id=correlation_id,
                    verification_id=verification_result['verification_id'],
                    is_valid=verification_result['is_valid'],
                    trust_score=verification_result['trust_score'],
                    validation_results=json.dumps(verification_result['validation_results']),
                    issuer_info=verification_result.get('issuer_info', ''),
                    wallet_attestation=verification_result.get('wallet_attestation', ''),
                    compliance_details=json.dumps(verification_result.get('compliance_details', {})),
                    timestamp=int(time.time())
                )
                
                # Track success metrics
                processing_time = time.time() - start_time
                self._track_presentation_verification_success(request, verification_result, processing_time)
                
                return response
                
            except Exception as e:
                # Track failure metrics
                processing_time = time.time() - start_time
                self._track_presentation_verification_failure(request, e, processing_time)
                
                logger.error(f"OID4VP presentation verification failed: {e}")
                
                return inspection_system_pb2.VerifyPresentationResponse(
                    correlation_id=correlation_id if 'correlation_id' in locals() else 'error',
                    is_valid=False,
                    error_message=str(e),
                    timestamp=int(time.time())
                )
    
    async def _validate_inspection_request(self, request: inspection_system_pb2.InspectRequest):
        """Validate inspection request parameters"""
        if not request.document_data:
            raise InspectionError("Document data is required")
        
        if not request.document_type:
            raise InspectionError("Document type is required")
        
        # Check payload size limits
        max_payload_size = self.inspection_config.get('security', {}).get('max_payload_size', 10485760)
        if len(request.document_data) > max_payload_size:
            raise InspectionError(f"Document data exceeds maximum size limit: {max_payload_size} bytes")
    
    async def _perform_inspection(self, request: inspection_system_pb2.InspectRequest, correlation_id: str) -> Dict[str, Any]:
        """Perform document inspection based on type"""
        inspection_id = f"insp_{int(time.time())}_{hash(correlation_id) % 100000}"
        
        try:
            # Route to appropriate verification method
            if request.document_type.lower() == 'passport':
                result = await self._inspect_passport(request, inspection_id, correlation_id)
            elif request.document_type.lower() == 'sd_jwt':
                result = await self._inspect_sd_jwt(request, inspection_id, correlation_id)
            elif request.document_type.lower() == 'mdl':
                result = await self._inspect_mdl(request, inspection_id, correlation_id)
            else:
                result = await self._inspect_generic_document(request, inspection_id, correlation_id)
            
            # Store inspection result
            await self._store_inspection_result(inspection_id, result, correlation_id)
            
            return result
            
        except Exception as e:
            logger.error(f"Inspection failed for {inspection_id}: {e}")
            raise InspectionError(f"Inspection failed: {e}")
    
    @trace_function("inspection_system.inspect_passport")
    async def _inspect_passport(self, request: inspection_system_pb2.InspectRequest, inspection_id: str, correlation_id: str) -> Dict[str, Any]:
        """Inspect passport document with crypto validation"""
        verification_details = {}
        security_features = []
        
        # Track passport verification workflow
        self.metrics.increment_counter(
            'verification_workflow_total',
            {
                'workflow_type': 'passport',
                'step': 'start',
                'complexity': 'high'
            }
        )
        
        try:
            # Step 1: Extract and validate MRZ
            if self.verification_config.get('crypto_validation', {}).get('mrz_validation_enabled', True):
                mrz_result = await self._validate_mrz(request.document_data)
                verification_details['mrz_validation'] = mrz_result
                
                self.metrics.increment_counter(
                    'passport_verification_total',
                    {
                        'verification_component': 'mrz',
                        'result': 'valid' if mrz_result['is_valid'] else 'invalid',
                        'document_type': 'passport'
                    }
                )
            
            # Step 2: Validate SOD (Security Object Document)
            if self.verification_config.get('crypto_validation', {}).get('sod_validation_enabled', True):
                sod_result = await self._validate_sod(request.document_data)
                verification_details['sod_validation'] = sod_result
                security_features.extend(sod_result.get('security_features', []))
                
                self.metrics.increment_counter(
                    'passport_verification_total',
                    {
                        'verification_component': 'sod',
                        'result': 'valid' if sod_result['is_valid'] else 'invalid',
                        'document_type': 'passport'
                    }
                )
            
            # Step 3: Certificate chain validation
            if self.verification_config.get('crypto_validation', {}).get('certificate_chain_validation', True):
                cert_result = await self._validate_certificate_chain(request.document_data)
                verification_details['certificate_validation'] = cert_result
                
                self.metrics.increment_counter(
                    'certificate_validation_total',
                    {
                        'validation_type': 'chain',
                        'certificate_type': 'passport_sod',
                        'result': 'valid' if cert_result['is_valid'] else 'invalid',
                        'chain_length': cert_result.get('chain_length', 0)
                    }
                )
            
            # Step 4: Trust anchor verification
            if self.verification_config.get('trust_verification', {}).get('issuer_trust_check', True):
                trust_result = await self._verify_trust_anchor(request.document_data, 'passport')
                verification_details['trust_verification'] = trust_result
                
                self.metrics.increment_counter(
                    'trust_verification_total',
                    {
                        'trust_type': 'issuer',
                        'entity_type': 'passport_authority',
                        'result': 'trusted' if trust_result['is_trusted'] else 'untrusted',
                        'verification_source': trust_result.get('source', 'unknown')
                    }
                )
            
            # Calculate overall confidence score
            confidence_score = self._calculate_passport_confidence(verification_details)
            
            # Determine overall result
            verification_result = inspection_system_pb2.VerificationResult.VALID
            if confidence_score < 0.7:
                verification_result = inspection_system_pb2.VerificationResult.SUSPICIOUS
            if confidence_score < 0.5:
                verification_result = inspection_system_pb2.VerificationResult.INVALID
            
            # Check compliance
            compliance_status = await self._check_passport_compliance(verification_details)
            
            return {
                'inspection_id': inspection_id,
                'verification_result': verification_result,
                'confidence_score': confidence_score,
                'validation_details': verification_details,
                'security_features': security_features,
                'compliance_status': compliance_status
            }
            
        except Exception as e:
            logger.error(f"Passport inspection failed: {e}")
            raise VerificationError(f"Passport verification failed: {e}")
    
    @trace_function("inspection_system.inspect_sd_jwt")
    async def _inspect_sd_jwt(self, request: inspection_system_pb2.InspectRequest, inspection_id: str, correlation_id: str) -> Dict[str, Any]:
        """Inspect SD-JWT document"""
        verification_details = {}
        
        # Track SD-JWT verification workflow
        self.metrics.increment_counter(
            'verification_workflow_total',
            {
                'workflow_type': 'sd_jwt',
                'step': 'start',
                'complexity': 'medium'
            }
        )
        
        try:
            # Parse SD-JWT
            sd_jwt_data = json.loads(request.document_data.decode('utf-8'))
            
            # Step 1: Validate JWT structure
            jwt_validation = await self._validate_jwt_structure(sd_jwt_data)
            verification_details['jwt_structure'] = jwt_validation
            
            self.metrics.increment_counter(
                'sd_jwt_verification_total',
                {
                    'verification_step': 'structure',
                    'result': 'valid' if jwt_validation['is_valid'] else 'invalid',
                    'issuer_type': jwt_validation.get('issuer_type', 'unknown')
                }
            )
            
            # Step 2: Validate selective disclosures
            disclosure_validation = await self._validate_selective_disclosures(sd_jwt_data)
            verification_details['disclosure_validation'] = disclosure_validation
            
            self.metrics.increment_counter(
                'sd_jwt_verification_total',
                {
                    'verification_step': 'disclosures',
                    'result': 'valid' if disclosure_validation['is_valid'] else 'invalid',
                    'disclosure_count': disclosure_validation.get('disclosure_count', 0)
                }
            )
            
            # Step 3: Verify issuer signature
            signature_validation = await self._verify_sd_jwt_signature(sd_jwt_data)
            verification_details['signature_validation'] = signature_validation
            
            self.metrics.increment_counter(
                'sd_jwt_verification_total',
                {
                    'verification_step': 'signature',
                    'result': 'valid' if signature_validation['is_valid'] else 'invalid',
                    'issuer_type': signature_validation.get('issuer_type', 'unknown')
                }
            )
            
            # Step 4: Trust verification
            if self.verification_config.get('trust_verification', {}).get('issuer_trust_check', True):
                trust_result = await self._verify_trust_anchor(request.document_data, 'sd_jwt')
                verification_details['trust_verification'] = trust_result
            
            # Calculate confidence score
            confidence_score = self._calculate_sd_jwt_confidence(verification_details)
            
            # Determine verification result
            verification_result = inspection_system_pb2.VerificationResult.VALID
            if confidence_score < 0.8:
                verification_result = inspection_system_pb2.VerificationResult.SUSPICIOUS
            if confidence_score < 0.6:
                verification_result = inspection_system_pb2.VerificationResult.INVALID
            
            # Check compliance
            compliance_status = await self._check_sd_jwt_compliance(verification_details)
            
            return {
                'inspection_id': inspection_id,
                'verification_result': verification_result,
                'confidence_score': confidence_score,
                'validation_details': verification_details,
                'security_features': ['selective_disclosure', 'digital_signature'],
                'compliance_status': compliance_status
            }
            
        except Exception as e:
            logger.error(f"SD-JWT inspection failed: {e}")
            raise VerificationError(f"SD-JWT verification failed: {e}")
    
    async def _verify_oid4vp_presentation(self, request: inspection_system_pb2.VerifyPresentationRequest, correlation_id: str) -> Dict[str, Any]:
        """Verify OID4VP presentation"""
        verification_id = f"oid4vp_{int(time.time())}_{hash(correlation_id) % 100000}"
        
        try:
            # Parse presentation
            presentation_data = json.loads(request.presentation_data.decode('utf-8'))
            
            # Step 1: Validate presentation definition compliance
            pd_validation = await self._validate_presentation_definition_compliance(
                presentation_data, 
                request.presentation_definition
            )
            
            self.metrics.increment_counter(
                'oid4vp_presentation_total',
                {
                    'presentation_type': request.presentation_type,
                    'validation_step': 'presentation_definition',
                    'result': 'valid' if pd_validation['is_compliant'] else 'invalid',
                    'compliance_level': pd_validation.get('compliance_level', 'unknown')
                }
            )
            
            # Step 2: Verify wallet attestation
            wallet_validation = {}
            if self.verification_config.get('trust_verification', {}).get('wallet_attestation_check', True):
                wallet_validation = await self._verify_wallet_attestation(presentation_data)
                
                self.metrics.increment_counter(
                    'trust_verification_total',
                    {
                        'trust_type': 'wallet_attestation',
                        'entity_type': 'wallet',
                        'result': 'trusted' if wallet_validation.get('is_trusted', False) else 'untrusted',
                        'verification_source': 'attestation'
                    }
                )
            
            # Step 3: Validate contained credentials
            credential_validations = []
            for credential in presentation_data.get('verifiable_credentials', []):
                cred_validation = await self._validate_presentation_credential(credential)
                credential_validations.append(cred_validation)
            
            # Step 4: Check revocation status
            revocation_results = []
            if self.verification_config.get('trust_verification', {}).get('revocation_check', True):
                for credential in presentation_data.get('verifiable_credentials', []):
                    revocation_result = await self._check_credential_revocation(credential)
                    revocation_results.append(revocation_result)
            
            # Calculate trust score
            trust_score = self._calculate_presentation_trust_score(
                pd_validation, wallet_validation, credential_validations, revocation_results
            )
            
            # Determine validity
            is_valid = (
                pd_validation.get('is_compliant', False) and
                wallet_validation.get('is_trusted', True) and
                all(cv.get('is_valid', False) for cv in credential_validations) and
                all(rr.get('is_not_revoked', True) for rr in revocation_results)
            )
            
            return {
                'verification_id': verification_id,
                'is_valid': is_valid,
                'trust_score': trust_score,
                'validation_results': {
                    'presentation_definition': pd_validation,
                    'wallet_attestation': wallet_validation,
                    'credentials': credential_validations,
                    'revocation': revocation_results
                },
                'issuer_info': self._extract_issuer_info(presentation_data),
                'wallet_attestation': wallet_validation.get('attestation_data', ''),
                'compliance_details': pd_validation
            }
            
        except Exception as e:
            logger.error(f"OID4VP presentation verification failed: {e}")
            raise VerificationError(f"OID4VP verification failed: {e}")
    
    def _track_inspection_success(self, request, result: Dict[str, Any], processing_time: float):
        """Track successful inspection metrics"""
        # Track processing time
        self.metrics.observe_histogram(
            'inspection_processing_duration_seconds',
            processing_time,
            {'operation': 'inspect', 'document_type': request.document_type}
        )
        
        # Track business metrics
        self.business_metrics.track_event(
            'inspection_completed',
            {
                'document_type': request.document_type,
                'verification_result': str(result['verification_result']),
                'confidence_score': result['confidence_score'],
                'processing_time': processing_time,
                'security_features_count': len(result.get('security_features', []))
            }
        )
        
        # Track quality metrics
        if result['confidence_score'] >= 0.9:
            confidence_category = 'high'
        elif result['confidence_score'] >= 0.7:
            confidence_category = 'medium'
        else:
            confidence_category = 'low'
            
        self.metrics.increment_counter(
            'verification_workflow_total',
            {
                'workflow_type': request.document_type.lower(),
                'step': 'completed',
                'result': 'success',
                'complexity': confidence_category
            }
        )
    
    def _track_inspection_failure(self, request, error: Exception, processing_time: float):
        """Track failed inspection metrics"""
        # Track failure
        self.metrics.increment_counter(
            'inspection_operations_total',
            {
                'operation': 'inspect',
                'document_type': request.document_type,
                'result': 'failed',
                'verification_type': request.verification_type
            }
        )
        
        # Track error type
        error_type = type(error).__name__
        self.metrics.increment_counter(
            'inspection_errors_total',
            {'error_type': error_type, 'document_type': request.document_type}
        )
        
        # Log security event for potential security violations
        if isinstance(error, (TrustValidationError, ComplianceError)):
            self.security_logger.log_security_event(
                'verification_failure',
                {
                    'document_type': request.document_type,
                    'error_type': error_type,
                    'error_message': str(error),
                    'processing_time': processing_time
                }
            )
    
    def _track_presentation_verification_success(self, request, result: Dict[str, Any], processing_time: float):
        """Track successful presentation verification metrics"""
        self.metrics.observe_histogram(
            'presentation_verification_duration_seconds',
            processing_time,
            {'presentation_type': request.presentation_type}
        )
        
        self.business_metrics.track_event(
            'presentation_verified',
            {
                'presentation_type': request.presentation_type,
                'is_valid': result['is_valid'],
                'trust_score': result['trust_score'],
                'processing_time': processing_time
            }
        )
    
    def _track_presentation_verification_failure(self, request, error: Exception, processing_time: float):
        """Track failed presentation verification metrics"""
        self.metrics.increment_counter(
            'oid4vp_presentation_total',
            {
                'presentation_type': request.presentation_type,
                'validation_step': 'failed',
                'result': 'error'
            }
        )
        
        self.security_logger.log_security_event(
            'presentation_verification_failure',
            {
                'presentation_type': request.presentation_type,
                'error_type': type(error).__name__,
                'error_message': str(error)
            }
        )
    
    # Implementation of verification helper methods would continue here...
    # These methods would contain the actual verification logic for:
    # - MRZ validation
    # - SOD validation  
    # - Certificate chain validation
    # - Trust anchor verification
    # - SD-JWT validation
    # - OID4VP presentation verification
    # - Compliance checking
    # - Confidence score calculation
    
    async def _validate_mrz(self, document_data: bytes) -> Dict[str, Any]:
        """Validate Machine Readable Zone"""
        # Implementation would parse and validate MRZ data
        return {'is_valid': True, 'confidence': 0.95}
    
    async def _validate_sod(self, document_data: bytes) -> Dict[str, Any]:
        """Validate Security Object Document"""
        # Implementation would validate SOD signature and data integrity
        return {'is_valid': True, 'security_features': ['digital_signature', 'data_integrity']}
    
    async def _validate_certificate_chain(self, document_data: bytes) -> Dict[str, Any]:
        """Validate certificate chain"""
        # Implementation would verify certificate chain up to trust anchor
        return {'is_valid': True, 'chain_length': 3}
    
    async def _verify_trust_anchor(self, document_data: bytes, doc_type: str) -> Dict[str, Any]:
        """Verify against trust anchor"""
        if self.trust_anchor_client:
            # Use trust anchor service for verification
            pass
        return {'is_trusted': True, 'source': 'trust_anchor_service'}
    
    def _calculate_passport_confidence(self, verification_details: Dict[str, Any]) -> float:
        """Calculate passport verification confidence score"""
        # Implementation would weight different verification components
        return 0.9
    
    def _calculate_sd_jwt_confidence(self, verification_details: Dict[str, Any]) -> float:
        """Calculate SD-JWT verification confidence score"""
        return 0.85
    
    def _calculate_presentation_trust_score(self, pd_validation, wallet_validation, 
                                          credential_validations, revocation_results) -> float:
        """Calculate OID4VP presentation trust score"""
        return 0.88
    
    async def _check_passport_compliance(self, verification_details: Dict[str, Any]) -> str:
        """Check passport compliance with regulations"""
        return "compliant"
    
    async def _check_sd_jwt_compliance(self, verification_details: Dict[str, Any]) -> str:
        """Check SD-JWT compliance"""
        return "compliant"
    
    async def _store_inspection_result(self, inspection_id: str, result: Dict[str, Any], correlation_id: str):
        """Store inspection result in database"""
        async with self.db_manager.get_session() as session:
            # Implementation would store result in database
            pass
    
    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.trust_anchor_client:
                await self.trust_anchor_client.close()
            if self.document_signer_client:
                await self.document_signer_client.close()
            
            await self.db_manager.close()
            await self.storage_manager.close()
            await self.key_vault.close()
            await self.observability.cleanup()
            
            logger.info("Inspection System service cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


async def create_server(config: Config) -> UnifiedGrpcServer:
    """Create and configure the gRPC server"""
    try:
        # Initialize service
        inspection_service = InspectionSystemService(config)
        await inspection_service.initialize()
        
        # Create unified gRPC server
        server = UnifiedGrpcServer(config, "inspection-system")
        
        # Add service to server
        inspection_system_pb2_grpc.add_InspectionSystemServicer_to_server(
            inspection_service, server.server
        )
        
        # Add health check service
        health_servicer = health.HealthServicer()
        health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server.server)
        
        # Configure health status
        health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
        health_servicer.set("inspection-system", health_pb2.HealthCheckResponse.SERVING)
        
        # Enable reflection
        if config.get('grpc', {}).get('server', {}).get('reflection_enabled', True):
            service_names = (
                inspection_system_pb2.DESCRIPTOR.services_by_name['InspectionSystem'].full_name,
                health_pb2.DESCRIPTOR.services_by_name['Health'].full_name,
                reflection.SERVICE_NAME,
            )
            reflection.enable_server_reflection(service_names, server.server)
        
        # Store service reference for cleanup
        server._inspection_service = inspection_service
        
        return server
        
    except Exception as e:
        logger.error(f"Failed to create Inspection System server: {e}")
        raise


async def main():
    """Main entry point"""
    try:
        # Load configuration
        config = Config()
        
        # Create and start server
        server = await create_server(config)
        
        # Start server
        await server.start()
        
        logger.info("Inspection System service started successfully")
        
        # Wait for termination
        await server.wait_for_termination()
        
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
    finally:
        # Cleanup
        if 'server' in locals():
            await server._inspection_service.cleanup()
            await server.stop()


if __name__ == '__main__':
    asyncio.run(main())