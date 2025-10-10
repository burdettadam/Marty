"""
Modern Consistency Engine Service with Unified Observability
Handles cross-zone validation, field mapping, consistency rules, and audit trails
"""

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple

import grpc
from grpc import aio
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection
from google.protobuf.timestamp_pb2 import Timestamp

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
from src.utils.redis_manager import RedisManager

# Import service-specific components
from src.proto import consistency_engine_pb2, consistency_engine_pb2_grpc
from src.services.cedar_policy_engine import CedarPolicyEngine, ValidationContext
from src.utils.config import Config
from src.utils.exceptions import (
    ConsistencyError,
    ValidationError,
    PolicyViolationError
)

logger = logging.getLogger(__name__)


@dataclass
class FieldMapping:
    """Maps canonical fields to zone-specific field names"""
    canonical_field: str
    zone_mappings: Dict[str, str] = field(default_factory=dict)
    data_type: str = "string"
    validation_regex: Optional[str] = None
    max_length: Optional[int] = None
    is_required: bool = False


@dataclass
class ConsistencyRule:
    """Defines a consistency rule between document zones"""
    rule_id: str
    name: str
    description: str
    source_zones: Set[str]
    target_zones: Set[str]
    applicable_fields: Set[str]
    rule_type: str
    is_critical: bool = True
    fuzzy_threshold: float = 0.8
    validation_function: Optional[str] = None


@dataclass
class AuditTrailEntry:
    """Audit trail entry for consistency checks"""
    audit_id: str
    request_id: str
    timestamp: datetime
    operation: str
    details: Dict[str, Any]
    result_status: str
    processing_time_ms: int
    context: Dict[str, str]


class ModernConsistencyEngine(consistency_engine_pb2_grpc.ConsistencyEngineServicer):
    """Modern Consistency Engine with comprehensive cross-zone validation"""
    
    def __init__(self, config: Config):
        self.config = config
        self.service_name = "consistency-engine"
        
        # Initialize unified observability
        self.observability = ObservabilityManager(
            service_name=self.service_name,
            config=config
        )
        self.metrics = MartyMetrics(config)
        self.business_metrics = BusinessMetricsTracker(config)
        self.security_logger = SecurityEventLogger(config)
        
        # Initialize storage and caching
        self.db_manager = DatabaseManager(config)
        self.redis_manager = RedisManager(config)
        
        # Initialize Cedar policy engine
        self.cedar_engine = CedarPolicyEngine()
        
        # Configuration
        self.consistency_config = config.get('consistency_engine', {})
        self.validation_mode = self.consistency_config.get('validation_mode', 'strict')
        
        # Initialize field mappings and rules
        self.field_mappings: Dict[str, FieldMapping] = {}
        self.consistency_rules: Dict[str, ConsistencyRule] = {}
        
        # Audit trail storage
        self.audit_trail: List[AuditTrailEntry] = []
        
        logger.info(f"Initialized {self.service_name} with observability framework")
    
    async def initialize(self):
        """Initialize service dependencies"""
        try:
            # Initialize database
            await self.db_manager.initialize()
            
            # Initialize Redis for caching
            await self.redis_manager.initialize()
            
            # Initialize Cedar policy engine
            if self.consistency_config.get('integration', {}).get('cedar_policy_engine_enabled', True):
                await self.cedar_engine.initialize()
            
            # Initialize field mappings and consistency rules
            await self._initialize_field_mappings()
            await self._initialize_consistency_rules()
            
            # Start health checks
            await self.observability.start_health_checks()
            
            logger.info("Modern Consistency Engine service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Modern Consistency Engine service: {e}")
            raise
    
    @trace_function("consistency_engine.check_consistency")
    async def CheckConsistency(self, request: consistency_engine_pb2.ConsistencyCheckRequest, context) -> consistency_engine_pb2.ConsistencyCheckResponse:
        """Main consistency checking endpoint"""
        start_time = time.time()
        audit_id = str(uuid.uuid4())
        
        with correlation_context():
            try:
                # Extract correlation ID
                correlation_id = context.get_trailing_metadata().get('x-correlation-id', 'unknown')
                
                # Track operation metrics
                self.metrics.increment_counter(
                    'consistency_operations_total',
                    {
                        'operation': 'check_consistency',
                        'zone_count': len(request.zone_data),
                        'rule_count': len(request.rules_to_check) or 'all'
                    }
                )
                
                logger.info(f"Starting consistency check: request_id={request.request_id}, "
                           f"zones={len(request.zone_data)}, correlation_id={correlation_id}")
                
                # Validate request
                await self._validate_consistency_request(request)
                
                # Extract and normalize field data from all zones
                normalized_data = await self._extract_normalized_data(request.zone_data)
                
                # Determine which rules to apply
                rules_to_apply = await self._determine_applicable_rules(request, normalized_data)
                
                # Execute consistency checks
                rule_results, critical_mismatches, warnings = await self._execute_consistency_checks(
                    rules_to_apply, normalized_data, request.fuzzy_match_threshold
                )
                
                # Calculate overall status and confidence
                overall_status, overall_confidence = self._calculate_overall_result(rule_results)
                
                # Generate response
                response = await self._build_consistency_response(
                    request.request_id,
                    audit_id,
                    overall_status,
                    rule_results,
                    critical_mismatches,
                    warnings,
                    overall_confidence,
                    start_time
                )
                
                # Store audit trail
                if request.include_audit_trail:
                    await self._store_audit_entry(
                        audit_id, request.request_id, start_time,
                        normalized_data, rules_to_apply, overall_status,
                        len(critical_mismatches) + len(warnings)
                    )
                
                # Track success metrics
                processing_time = time.time() - start_time
                self._track_consistency_success(request, response, processing_time)
                
                logger.info(f"Consistency check completed: audit_id={audit_id}, "
                           f"status={overall_status}, confidence={overall_confidence:.2f}")
                
                return response
                
            except Exception as e:
                # Track failure metrics
                processing_time = time.time() - start_time
                self._track_consistency_failure(request, e, processing_time)
                
                logger.error(f"Consistency check failed: {e}")
                
                # Return error response
                return self._create_error_response(request.request_id, str(e))
    
    @trace_function("consistency_engine.validate_field_mapping")
    async def ValidateFieldMapping(self, request: consistency_engine_pb2.FieldMappingRequest, context) -> consistency_engine_pb2.FieldMappingResponse:
        """Validate specific field mappings"""
        start_time = time.time()
        
        with correlation_context():
            try:
                correlation_id = context.get_trailing_metadata().get('x-correlation-id', 'unknown')
                
                # Track operation metrics
                self.metrics.increment_counter(
                    'field_validation_total',
                    {
                        'field_type': request.field_name,
                        'validation_type': 'mapping',
                        'zone_pair': f"{request.source_zone}_{request.target_zone}"
                    }
                )
                
                logger.info(f"Validating field mapping: field={request.field_name}, "
                           f"source={request.source_zone}, target={request.target_zone}")
                
                # Perform field mapping validation
                validation_result = await self._validate_field_mapping(
                    request.field_name,
                    request.source_zone,
                    request.target_zone,
                    request.source_value,
                    request.target_value
                )
                
                # Create response
                response = consistency_engine_pb2.FieldMappingResponse(
                    is_valid=validation_result['is_valid'],
                    confidence_score=validation_result['confidence_score'],
                    normalized_source_value=validation_result['normalized_source'],
                    normalized_target_value=validation_result['normalized_target'],
                    validation_details=json.dumps(validation_result['details'])
                )
                
                # Track success metrics
                processing_time = time.time() - start_time
                self._track_field_validation_success(request, validation_result, processing_time)
                
                return response
                
            except Exception as e:
                # Track failure metrics
                processing_time = time.time() - start_time
                self._track_field_validation_failure(request, e, processing_time)
                
                logger.error(f"Field mapping validation failed: {e}")
                
                return consistency_engine_pb2.FieldMappingResponse(
                    is_valid=False,
                    error_message=str(e)
                )
    
    @trace_function("consistency_engine.get_supported_rules")
    async def GetSupportedRules(self, request: consistency_engine_pb2.GetSupportedRulesRequest, context) -> consistency_engine_pb2.GetSupportedRulesResponse:
        """Get supported consistency rules"""
        try:
            logger.info("Retrieving supported consistency rules")
            
            # Build rule descriptions
            rule_descriptions = []
            for rule_id, rule in self.consistency_rules.items():
                rule_desc = consistency_engine_pb2.RuleDescription(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    rule_type=rule.rule_type,
                    is_critical=rule.is_critical,
                    applicable_zones=list(rule.source_zones.union(rule.target_zones)),
                    applicable_fields=list(rule.applicable_fields)
                )
                rule_descriptions.append(rule_desc)
            
            response = consistency_engine_pb2.GetSupportedRulesResponse(
                rules=rule_descriptions
            )
            
            # Track metrics
            self.metrics.increment_counter(
                'rule_execution_total',
                {
                    'rule_type': 'get_supported',
                    'result': 'success',
                    'rule_count': len(rule_descriptions)
                }
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to get supported rules: {e}")
            raise
    
    async def _validate_consistency_request(self, request: consistency_engine_pb2.ConsistencyCheckRequest):
        """Validate consistency check request"""
        if not request.request_id:
            raise ValidationError("Request ID is required")
        
        if not request.zone_data:
            raise ValidationError("Zone data is required")
        
        # Validate zone data structure
        for zone_data in request.zone_data:
            if not zone_data.fields:
                logger.warning(f"Empty fields for zone: {zone_data.zone}")
    
    async def _extract_normalized_data(self, zone_data_list) -> Dict[str, Dict[str, str]]:
        """Extract and normalize field data from all zones"""
        normalized_data = {}
        
        for zone_data in zone_data_list:
            zone_name = consistency_engine_pb2.DocumentZone.Name(zone_data.zone)
            normalized_data[zone_name] = {}
            
            # Track data extraction metrics
            self.metrics.increment_counter(
                'data_quality_total',
                {
                    'quality_metric': 'extraction',
                    'zone': zone_name,
                    'field_count': len(zone_data.fields)
                }
            )
            
            # Map zone-specific field names to canonical field names
            for zone_field_name, value in zone_data.fields.items():
                canonical_field = await self._map_to_canonical_field(zone_name, zone_field_name)
                if canonical_field:
                    normalized_value = self._normalize_field_value(canonical_field, value)
                    normalized_data[zone_name][canonical_field] = normalized_value
        
        return normalized_data
    
    async def _determine_applicable_rules(self, request: consistency_engine_pb2.ConsistencyCheckRequest, normalized_data: Dict[str, Dict[str, str]]) -> List[ConsistencyRule]:
        """Determine which consistency rules to apply"""
        available_zones = set(normalized_data.keys())
        
        if request.rules_to_check:
            # Use specific rules requested
            rules_to_apply = []
            for rule_enum in request.rules_to_check:
                rule_name = consistency_engine_pb2.ConsistencyRule.Name(rule_enum)
                if rule_name in self.consistency_rules:
                    rule = self.consistency_rules[rule_name]
                    # Check if rule is applicable to available zones
                    if rule.source_zones.intersection(available_zones) and rule.target_zones.intersection(available_zones):
                        rules_to_apply.append(rule)
        else:
            # Use all applicable rules
            rules_to_apply = []
            for rule in self.consistency_rules.values():
                if rule.source_zones.intersection(available_zones) and rule.target_zones.intersection(available_zones):
                    rules_to_apply.append(rule)
        
        logger.info(f"Applying {len(rules_to_apply)} consistency rules to {len(available_zones)} zones")
        return rules_to_apply
    
    async def _execute_consistency_checks(self, rules_to_apply: List[ConsistencyRule], normalized_data: Dict[str, Dict[str, str]], fuzzy_threshold: float) -> Tuple[List[Any], List[Any], List[Any]]:
        """Execute consistency checks for all applicable rules"""
        rule_results = []
        critical_mismatches = []
        warnings = []
        
        # Execute rules in parallel if enabled
        parallel_execution = self.consistency_config.get('performance', {}).get('enable_parallel_rule_execution', True)
        
        if parallel_execution:
            # Execute rules concurrently
            tasks = []
            for rule in rules_to_apply:
                task = self._execute_single_rule(rule, normalized_data, fuzzy_threshold)
                tasks.append(task)
            
            rule_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Handle any exceptions
            for i, result in enumerate(rule_results):
                if isinstance(result, Exception):
                    logger.error(f"Rule execution failed: {rules_to_apply[i].rule_id} - {result}")
                    rule_results[i] = self._create_error_rule_result(rules_to_apply[i], str(result))
        else:
            # Execute rules sequentially
            for rule in rules_to_apply:
                try:
                    rule_result = await self._execute_single_rule(rule, normalized_data, fuzzy_threshold)
                    rule_results.append(rule_result)
                except Exception as e:
                    logger.error(f"Rule execution failed: {rule.rule_id} - {e}")
                    rule_results.append(self._create_error_rule_result(rule, str(e)))
        
        # Categorize mismatches
        for rule_result in rule_results:
            if hasattr(rule_result, 'mismatches'):
                for mismatch in rule_result.mismatches:
                    if mismatch.severity_score >= self.consistency_config.get('consistency_rules', {}).get('critical_mismatch_threshold', 0.7):
                        critical_mismatches.append(mismatch)
                    else:
                        warnings.append(mismatch)
        
        return rule_results, critical_mismatches, warnings
    
    @trace_function("consistency_engine.execute_single_rule")
    async def _execute_single_rule(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]], fuzzy_threshold: float) -> Any:
        """Execute a single consistency rule"""
        start_time = time.time()
        
        try:
            logger.debug(f"Executing rule: {rule.rule_id}")
            
            # Track rule execution start
            self.metrics.increment_counter(
                'rule_execution_total',
                {
                    'rule_type': rule.rule_type,
                    'rule_id': rule.rule_id,
                    'result': 'started'
                }
            )
            
            # Execute rule based on type
            if rule.rule_type == "exact_match":
                result = await self._execute_exact_match_rule(rule, normalized_data)
            elif rule.rule_type == "fuzzy_match":
                result = await self._execute_fuzzy_match_rule(rule, normalized_data, fuzzy_threshold)
            elif rule.rule_type == "date_validation":
                result = await self._execute_date_validation_rule(rule, normalized_data)
            elif rule.rule_type == "checksum":
                result = await self._execute_checksum_rule(rule, normalized_data)
            elif rule.rule_type == "cross_reference":
                result = await self._execute_cross_reference_rule(rule, normalized_data)
            else:
                result = await self._execute_cedar_policy_rule(rule, normalized_data)
            
            # Track success metrics
            execution_time = time.time() - start_time
            execution_time_category = self._categorize_execution_time(execution_time)
            
            self.metrics.increment_counter(
                'rule_execution_total',
                {
                    'rule_type': rule.rule_type,
                    'rule_id': rule.rule_id,
                    'result': 'success',
                    'execution_time_category': execution_time_category
                }
            )
            
            self.metrics.observe_histogram(
                'rule_execution_duration_seconds',
                execution_time,
                {'rule_type': rule.rule_type, 'rule_id': rule.rule_id}
            )
            
            return result
            
        except Exception as e:
            # Track failure metrics
            execution_time = time.time() - start_time
            
            self.metrics.increment_counter(
                'rule_execution_total',
                {
                    'rule_type': rule.rule_type,
                    'rule_id': rule.rule_id,
                    'result': 'failed'
                }
            )
            
            logger.error(f"Rule execution failed: {rule.rule_id} - {e}")
            raise
    
    async def _execute_exact_match_rule(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]]) -> Any:
        """Execute exact match consistency rule"""
        mismatches = []
        
        # Compare fields across zones
        for field in rule.applicable_fields:
            field_values = {}
            
            # Collect field values from all relevant zones
            for zone in rule.source_zones.union(rule.target_zones):
                if zone in normalized_data and field in normalized_data[zone]:
                    field_values[zone] = normalized_data[zone][field]
            
            # Check for exact matches
            if len(field_values) > 1:
                values = list(field_values.values())
                zones = list(field_values.keys())
                
                for i in range(len(values)):
                    for j in range(i + 1, len(values)):
                        if values[i] != values[j]:
                            mismatch = self._create_field_mismatch(
                                field, zones[i], values[i], zones[j], values[j],
                                rule, "Exact match failed"
                            )
                            mismatches.append(mismatch)
                            
                            # Track cross-zone consistency
                            self.metrics.increment_counter(
                                'cross_zone_consistency_total',
                                {
                                    'source_zone': zones[i],
                                    'target_zone': zones[j],
                                    'field_name': field,
                                    'consistency_result': 'mismatch'
                                }
                            )
        
        # Create rule result
        confidence_score = 1.0 if not mismatches else max(0.0, 1.0 - (len(mismatches) * 0.2))
        status = consistency_engine_pb2.PASS if not mismatches else consistency_engine_pb2.FAIL
        
        return self._create_rule_result(rule, status, confidence_score, mismatches)
    
    async def _execute_fuzzy_match_rule(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]], fuzzy_threshold: float) -> Any:
        """Execute fuzzy match consistency rule"""
        mismatches = []
        
        # Use rule-specific threshold or provided threshold
        threshold = rule.fuzzy_threshold if rule.fuzzy_threshold else fuzzy_threshold
        
        # Compare fields across zones using fuzzy matching
        for field in rule.applicable_fields:
            field_values = {}
            
            # Collect field values from all relevant zones
            for zone in rule.source_zones.union(rule.target_zones):
                if zone in normalized_data and field in normalized_data[zone]:
                    field_values[zone] = normalized_data[zone][field]
            
            # Check for fuzzy matches
            if len(field_values) > 1:
                values = list(field_values.values())
                zones = list(field_values.keys())
                
                for i in range(len(values)):
                    for j in range(i + 1, len(values)):
                        similarity = SequenceMatcher(None, values[i], values[j]).ratio()
                        
                        if similarity < threshold:
                            mismatch = self._create_field_mismatch(
                                field, zones[i], values[i], zones[j], values[j],
                                rule, f"Fuzzy match failed: similarity {similarity:.2f} < {threshold:.2f}"
                            )
                            mismatches.append(mismatch)
                            
                            # Track fuzzy matching metrics
                            similarity_range = self._categorize_similarity(similarity)
                            self.metrics.increment_counter(
                                'fuzzy_matching_total',
                                {
                                    'match_type': 'field_comparison',
                                    'similarity_range': similarity_range,
                                    'field_type': field,
                                    'result': 'mismatch'
                                }
                            )
        
        # Create rule result
        confidence_score = 1.0 if not mismatches else max(0.0, 1.0 - (len(mismatches) * 0.15))
        status = consistency_engine_pb2.PASS if not mismatches else consistency_engine_pb2.WARNING
        
        return self._create_rule_result(rule, status, confidence_score, mismatches)
    
    async def _execute_date_validation_rule(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]]) -> Any:
        """Execute date validation consistency rule"""
        mismatches = []
        
        # Validate date formats and logical consistency
        for field in rule.applicable_fields:
            date_values = {}
            
            # Collect date values from all relevant zones
            for zone in rule.source_zones.union(rule.target_zones):
                if zone in normalized_data and field in normalized_data[zone]:
                    date_str = normalized_data[zone][field]
                    parsed_date = self._parse_date(date_str)
                    if parsed_date:
                        date_values[zone] = parsed_date
            
            # Check date consistency
            if len(date_values) > 1:
                dates = list(date_values.values())
                zones = list(date_values.keys())
                
                for i in range(len(dates)):
                    for j in range(i + 1, len(dates)):
                        # Check if dates are the same
                        if dates[i] != dates[j]:
                            mismatch = self._create_field_mismatch(
                                field, zones[i], str(dates[i]), zones[j], str(dates[j]),
                                rule, "Date values do not match"
                            )
                            mismatches.append(mismatch)
            
            # Validate logical date relationships (e.g., birth date < expiry date)
            if field == "DATE_OF_BIRTH" and "DATE_OF_EXPIRY" in [f for zone_data in normalized_data.values() for f in zone_data.keys()]:
                # Additional logic for date relationship validation
                pass
        
        confidence_score = 1.0 if not mismatches else max(0.0, 1.0 - (len(mismatches) * 0.25))
        status = consistency_engine_pb2.PASS if not mismatches else consistency_engine_pb2.FAIL
        
        return self._create_rule_result(rule, status, confidence_score, mismatches)
    
    async def _execute_checksum_rule(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]]) -> Any:
        """Execute checksum validation rule"""
        mismatches = []
        
        # Validate MRZ checksums
        if "MRZ" in normalized_data:
            mrz_data = normalized_data["MRZ"]
            
            # Validate different types of check digits
            checksum_validations = {
                "CHECK_DIGIT_DOCUMENT": self._validate_document_checksum,
                "CHECK_DIGIT_DOB": self._validate_dob_checksum,
                "CHECK_DIGIT_EXPIRY": self._validate_expiry_checksum,
                "CHECK_DIGIT_COMPOSITE": self._validate_composite_checksum
            }
            
            for check_digit_field, validation_func in checksum_validations.items():
                if check_digit_field in rule.applicable_fields:
                    is_valid = validation_func(mrz_data)
                    if not is_valid:
                        mismatch = self._create_checksum_mismatch(check_digit_field, rule)
                        mismatches.append(mismatch)
        
        confidence_score = 1.0 if not mismatches else 0.0
        status = consistency_engine_pb2.PASS if not mismatches else consistency_engine_pb2.FAIL
        
        return self._create_rule_result(rule, status, confidence_score, mismatches)
    
    async def _execute_cross_reference_rule(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]]) -> Any:
        """Execute cross-reference validation rule"""
        mismatches = []
        
        # Validate cross-references between zones
        for field in rule.applicable_fields:
            # Check consistency across multiple zones for critical fields
            if field in ["DOCUMENT_NUMBER", "DATE_OF_BIRTH", "DATE_OF_EXPIRY"]:
                zone_values = {}
                for zone in normalized_data:
                    if field in normalized_data[zone]:
                        zone_values[zone] = normalized_data[zone][field]
                
                # Validate cross-references
                if len(zone_values) > 1:
                    values = list(zone_values.values())
                    if not all(v == values[0] for v in values):
                        zones = list(zone_values.keys())
                        mismatch = self._create_cross_reference_mismatch(
                            field, zones, values, rule
                        )
                        mismatches.append(mismatch)
        
        confidence_score = 1.0 if not mismatches else max(0.0, 1.0 - (len(mismatches) * 0.3))
        status = consistency_engine_pb2.PASS if not mismatches else consistency_engine_pb2.FAIL
        
        return self._create_rule_result(rule, status, confidence_score, mismatches)
    
    async def _execute_cedar_policy_rule(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]]) -> Any:
        """Execute rule using Cedar policy engine"""
        if not self.consistency_config.get('integration', {}).get('cedar_policy_engine_enabled', True):
            # Skip Cedar evaluation if disabled
            return self._create_rule_result(rule, consistency_engine_pb2.PASS, 1.0, [])
        
        try:
            # Create validation context
            context = ValidationContext(
                principal={"type": "ConsistencyEngine", "id": "consistency-check"},
                action={"type": "Action", "id": f"validate_{rule.rule_type}"},
                resource={"type": "DocumentData", "id": "cross-zone-data"},
                context={"normalized_data": normalized_data, "rule": rule.__dict__}
            )
            
            # Evaluate policy
            policy_result = await self.cedar_engine.evaluate_policy(
                f"consistency_{rule.rule_id.lower()}", context
            )
            
            status = consistency_engine_pb2.PASS if policy_result.decision == "Allow" else consistency_engine_pb2.FAIL
            confidence_score = policy_result.confidence if hasattr(policy_result, 'confidence') else 1.0
            
            return self._create_rule_result(rule, status, confidence_score, [])
            
        except Exception as e:
            logger.error(f"Cedar policy evaluation failed for rule {rule.rule_id}: {e}")
            return self._create_rule_result(rule, consistency_engine_pb2.ERROR, 0.0, [])
    
    # Helper methods for field mapping, normalization, and validation
    async def _map_to_canonical_field(self, zone_name: str, zone_field_name: str) -> Optional[str]:
        """Map zone-specific field name to canonical field name"""
        # Check cache first
        cache_key = f"field_mapping:{zone_name}:{zone_field_name}"
        cached_mapping = await self.redis_manager.get(cache_key)
        
        if cached_mapping:
            return cached_mapping
        
        # Search field mappings
        for canonical_field, mapping in self.field_mappings.items():
            if zone_name in mapping.zone_mappings and mapping.zone_mappings[zone_name] == zone_field_name:
                # Cache the result
                await self.redis_manager.set(cache_key, canonical_field, ttl=3600)
                return canonical_field
        
        return None
    
    def _normalize_field_value(self, canonical_field: str, value: str) -> str:
        """Normalize field value based on field type"""
        if not value:
            return value
        
        # Get field mapping for normalization rules
        field_mapping = self.field_mappings.get(canonical_field)
        if not field_mapping:
            return value
        
        normalized = value
        
        # Apply normalization based on field type
        if field_mapping.data_type == "date":
            normalized = self._normalize_date(value)
        elif field_mapping.data_type == "name":
            normalized = self._normalize_name(value)
        elif field_mapping.data_type == "string":
            normalized = self._normalize_string(value)
        
        return normalized
    
    def _normalize_date(self, date_str: str) -> str:
        """Normalize date string to standard format"""
        # Implementation would handle various date formats
        return date_str.strip().upper()
    
    def _normalize_name(self, name_str: str) -> str:
        """Normalize name string"""
        if self.consistency_config.get('field_mappings', {}).get('normalize_names', True):
            return name_str.strip().upper().replace(' ', '')
        return name_str.strip()
    
    def _normalize_string(self, value: str) -> str:
        """Normalize general string value"""
        normalized = value.strip()
        
        if self.consistency_config.get('field_mappings', {}).get('case_insensitive_matching', True):
            normalized = normalized.upper()
        
        if self.consistency_config.get('field_mappings', {}).get('whitespace_normalization', True):
            normalized = re.sub(r'\s+', ' ', normalized)
        
        return normalized
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string to datetime object"""
        date_formats = self.consistency_config.get('field_mappings', {}).get('date_formats', [])
        
        for fmt in date_formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        return None
    
    # Validation helper methods
    def _validate_document_checksum(self, mrz_data: Dict[str, str]) -> bool:
        """Validate document number checksum"""
        # Implementation would validate MRZ document number check digit
        return True
    
    def _validate_dob_checksum(self, mrz_data: Dict[str, str]) -> bool:
        """Validate date of birth checksum"""
        # Implementation would validate MRZ DOB check digit
        return True
    
    def _validate_expiry_checksum(self, mrz_data: Dict[str, str]) -> bool:
        """Validate expiry date checksum"""
        # Implementation would validate MRZ expiry check digit
        return True
    
    def _validate_composite_checksum(self, mrz_data: Dict[str, str]) -> bool:
        """Validate composite checksum"""
        # Implementation would validate MRZ composite check digit
        return True
    
    # Result creation helper methods
    def _create_rule_result(self, rule: ConsistencyRule, status: int, confidence_score: float, mismatches: List[Any]) -> Any:
        """Create a rule result object"""
        # Implementation would create protobuf RuleCheckResult
        return {
            'rule_id': rule.rule_id,
            'status': status,
            'confidence_score': confidence_score,
            'mismatches': mismatches
        }
    
    def _create_field_mismatch(self, field: str, source_zone: str, source_value: str, 
                             target_zone: str, target_value: str, rule: ConsistencyRule, 
                             explanation: str) -> Any:
        """Create a field mismatch object"""
        return {
            'field': field,
            'source_zone': source_zone,
            'source_value': source_value,
            'target_zone': target_zone,
            'target_value': target_value,
            'rule_id': rule.rule_id,
            'explanation': explanation,
            'severity_score': 0.8 if rule.is_critical else 0.5
        }
    
    def _create_checksum_mismatch(self, check_digit_field: str, rule: ConsistencyRule) -> Any:
        """Create a checksum mismatch object"""
        return {
            'field': check_digit_field,
            'rule_id': rule.rule_id,
            'explanation': f"Checksum validation failed for {check_digit_field}",
            'severity_score': 0.9
        }
    
    def _create_cross_reference_mismatch(self, field: str, zones: List[str], values: List[str], rule: ConsistencyRule) -> Any:
        """Create a cross-reference mismatch object"""
        return {
            'field': field,
            'zones': zones,
            'values': values,
            'rule_id': rule.rule_id,
            'explanation': f"Cross-reference validation failed for {field}",
            'severity_score': 0.8
        }
    
    def _create_error_rule_result(self, rule: ConsistencyRule, error_msg: str) -> Any:
        """Create an error rule result"""
        return {
            'rule_id': rule.rule_id,
            'status': consistency_engine_pb2.ERROR,
            'confidence_score': 0.0,
            'error_message': error_msg,
            'mismatches': []
        }
    
    def _calculate_overall_result(self, rule_results: List[Any]) -> Tuple[int, float]:
        """Calculate overall consistency status and confidence"""
        if not rule_results:
            return consistency_engine_pb2.INCOMPLETE, 0.0
        
        # Calculate overall status
        has_failures = any(r.get('status') == consistency_engine_pb2.FAIL for r in rule_results)
        has_warnings = any(r.get('status') == consistency_engine_pb2.WARNING for r in rule_results)
        has_errors = any(r.get('status') == consistency_engine_pb2.ERROR for r in rule_results)
        
        if has_errors:
            overall_status = consistency_engine_pb2.ERROR
        elif has_failures:
            overall_status = consistency_engine_pb2.FAIL
        elif has_warnings:
            overall_status = consistency_engine_pb2.WARNING
        else:
            overall_status = consistency_engine_pb2.PASS
        
        # Calculate overall confidence
        confidence_scores = [r.get('confidence_score', 0.0) for r in rule_results if 'confidence_score' in r]
        overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        return overall_status, overall_confidence
    
    # Metrics tracking helper methods
    def _track_consistency_success(self, request, response, processing_time: float):
        """Track successful consistency check metrics"""
        self.metrics.observe_histogram(
            'consistency_processing_duration_seconds',
            processing_time,
            {
                'operation': 'check_consistency',
                'zone_count': len(request.zone_data)
            }
        )
        
        self.business_metrics.track_event(
            'consistency_check_completed',
            {
                'zone_count': len(request.zone_data),
                'overall_status': str(response.overall_status),
                'overall_confidence': response.overall_confidence,
                'critical_mismatches': len(getattr(response, 'critical_mismatches', [])),
                'processing_time': processing_time
            }
        )
    
    def _track_consistency_failure(self, request, error: Exception, processing_time: float):
        """Track failed consistency check metrics"""
        self.metrics.increment_counter(
            'consistency_operations_total',
            {
                'operation': 'check_consistency',
                'result': 'failed',
                'zone_count': len(request.zone_data)
            }
        )
        
        self.security_logger.log_security_event(
            'consistency_check_failure',
            {
                'request_id': request.request_id,
                'error_type': type(error).__name__,
                'error_message': str(error),
                'processing_time': processing_time
            }
        )
    
    def _track_field_validation_success(self, request, result: Dict[str, Any], processing_time: float):
        """Track successful field validation metrics"""
        self.metrics.increment_counter(
            'field_validation_total',
            {
                'field_type': request.field_name,
                'validation_type': 'mapping',
                'result': 'valid' if result['is_valid'] else 'invalid'
            }
        )
        
        self.business_metrics.track_event(
            'field_validation_completed',
            {
                'field_name': request.field_name,
                'is_valid': result['is_valid'],
                'confidence_score': result['confidence_score'],
                'processing_time': processing_time
            }
        )
    
    def _track_field_validation_failure(self, request, error: Exception, processing_time: float):
        """Track failed field validation metrics"""
        self.metrics.increment_counter(
            'field_validation_total',
            {
                'field_type': request.field_name,
                'validation_type': 'mapping',
                'result': 'error'
            }
        )
    
    # Utility helper methods
    def _categorize_execution_time(self, execution_time: float) -> str:
        """Categorize execution time for metrics"""
        if execution_time < 0.1:
            return "fast"
        elif execution_time < 0.5:
            return "medium"
        elif execution_time < 2.0:
            return "slow"
        else:
            return "very_slow"
    
    def _categorize_similarity(self, similarity: float) -> str:
        """Categorize similarity score for metrics"""
        if similarity >= 0.9:
            return "high"
        elif similarity >= 0.7:
            return "medium"
        elif similarity >= 0.5:
            return "low"
        else:
            return "very_low"
    
    # Initialization methods
    async def _initialize_field_mappings(self):
        """Initialize canonical field mappings for different zones"""
        # Implementation would load field mappings from configuration
        self.field_mappings = {
            "DOCUMENT_NUMBER": FieldMapping(
                canonical_field="DOCUMENT_NUMBER",
                zone_mappings={
                    "VISUAL_OCR": "document_number",
                    "MRZ": "document_number",
                    "BARCODE_1D": "doc_num",
                    "BARCODE_2D": "document_number",
                    "RFID_CHIP": "document_number"
                },
                data_type="string",
                validation_regex=r"^[A-Z0-9]{8,9}$",
                is_required=True
            ),
            # Additional field mappings would be loaded here
        }
    
    async def _initialize_consistency_rules(self):
        """Initialize consistency validation rules"""
        # Implementation would load rules from configuration
        self.consistency_rules = {
            "FIELD_EXACT_MATCH": ConsistencyRule(
                rule_id="FIELD_EXACT_MATCH",
                name="Exact Field Match",
                description="Fields must match exactly across zones",
                source_zones={"VISUAL_OCR", "MRZ", "BARCODE_1D", "BARCODE_2D", "RFID_CHIP"},
                target_zones={"VISUAL_OCR", "MRZ", "BARCODE_1D", "BARCODE_2D", "RFID_CHIP"},
                applicable_fields={"DOCUMENT_NUMBER", "NATIONALITY", "ISSUING_COUNTRY", "GENDER"},
                rule_type="exact_match",
                is_critical=True
            ),
            # Additional rules would be loaded here
        }
    
    # Additional helper methods for response building, audit storage, etc.
    async def _build_consistency_response(self, request_id: str, audit_id: str, overall_status: int,
                                        rule_results: List[Any], critical_mismatches: List[Any],
                                        warnings: List[Any], overall_confidence: float,
                                        start_time: float) -> consistency_engine_pb2.ConsistencyCheckResponse:
        """Build consistency check response"""
        # Implementation would create protobuf response
        response = consistency_engine_pb2.ConsistencyCheckResponse()
        response.request_id = request_id
        response.audit_id = audit_id
        response.overall_status = overall_status
        response.overall_confidence = overall_confidence
        # Add rule results, mismatches, etc.
        return response
    
    async def _store_audit_entry(self, audit_id: str, request_id: str, start_time: float,
                               normalized_data: Dict[str, Dict[str, str]], rules_to_apply: List[ConsistencyRule],
                               overall_status: int, mismatches_count: int):
        """Store audit trail entry"""
        entry = AuditTrailEntry(
            audit_id=audit_id,
            request_id=request_id,
            timestamp=datetime.fromtimestamp(start_time),
            operation="consistency_check",
            details={
                "zones": list(normalized_data.keys()),
                "rules": [rule.rule_id for rule in rules_to_apply],
                "overall_status": overall_status,
                "mismatches_count": mismatches_count
            },
            result_status=str(overall_status),
            processing_time_ms=int((time.time() - start_time) * 1000),
            context={}
        )
        
        # Store in database and/or audit trail
        async with self.db_manager.get_session() as session:
            # Implementation would store audit entry
            pass
    
    def _create_error_response(self, request_id: str, error_message: str) -> consistency_engine_pb2.ConsistencyCheckResponse:
        """Create error response"""
        response = consistency_engine_pb2.ConsistencyCheckResponse()
        response.request_id = request_id
        response.overall_status = consistency_engine_pb2.ERROR
        response.error.code = consistency_engine_pb2.ERROR_CODE_INTERNAL
        response.error.message = f"Consistency check failed: {error_message}"
        return response
    
    async def _validate_field_mapping(self, field_name: str, source_zone: str, target_zone: str,
                                    source_value: str, target_value: str) -> Dict[str, Any]:
        """Validate specific field mapping"""
        # Implementation would perform field-specific validation
        return {
            'is_valid': True,
            'confidence_score': 0.95,
            'normalized_source': source_value,
            'normalized_target': target_value,
            'details': {'validation_method': 'exact_match'}
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        try:
            await self.db_manager.close()
            await self.redis_manager.close()
            
            if self.consistency_config.get('integration', {}).get('cedar_policy_engine_enabled', True):
                await self.cedar_engine.cleanup()
            
            await self.observability.cleanup()
            
            logger.info("Modern Consistency Engine service cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


async def create_server(config: Config) -> UnifiedGrpcServer:
    """Create and configure the gRPC server"""
    try:
        # Initialize service
        consistency_service = ModernConsistencyEngine(config)
        await consistency_service.initialize()
        
        # Create unified gRPC server
        server = UnifiedGrpcServer(config, "consistency-engine")
        
        # Add service to server
        consistency_engine_pb2_grpc.add_ConsistencyEngineServicer_to_server(
            consistency_service, server.server
        )
        
        # Add health check service
        health_servicer = health.HealthServicer()
        health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server.server)
        
        # Configure health status
        health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
        health_servicer.set("consistency-engine", health_pb2.HealthCheckResponse.SERVING)
        
        # Enable reflection
        if config.get('grpc', {}).get('server', {}).get('reflection_enabled', True):
            service_names = (
                consistency_engine_pb2.DESCRIPTOR.services_by_name['ConsistencyEngine'].full_name,
                health_pb2.DESCRIPTOR.services_by_name['Health'].full_name,
                reflection.SERVICE_NAME,
            )
            reflection.enable_server_reflection(service_names, server.server)
        
        # Store service reference for cleanup
        server._consistency_service = consistency_service
        
        return server
        
    except Exception as e:
        logger.error(f"Failed to create Modern Consistency Engine server: {e}")
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
        
        logger.info("Modern Consistency Engine service started successfully")
        
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
            await server._consistency_service.cleanup()
            await server.stop()


if __name__ == '__main__':
    asyncio.run(main())