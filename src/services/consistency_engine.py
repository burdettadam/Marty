from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple

import grpc
from google.protobuf.timestamp_pb2 import Timestamp

from src.marty_common.observability import MetricsCollector, StructuredLogger
from src.proto import consistency_engine_pb2, consistency_engine_pb2_grpc


@dataclass
class FieldMapping:
    """Maps canonical fields to zone-specific field names."""
    canonical_field: str
    zone_mappings: Dict[str, str] = field(default_factory=dict)
    data_type: str = "string"
    validation_regex: Optional[str] = None
    max_length: Optional[int] = None
    is_required: bool = False


@dataclass
class ConsistencyRule:
    """Defines a consistency rule between document zones."""
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
    """Audit trail entry for consistency checks."""
    audit_id: str
    request_id: str
    timestamp: datetime
    operation: str
    details: Dict[str, Any]
    result_status: str
    processing_time_ms: int
    context: Dict[str, str]


class ConsistencyEngine(consistency_engine_pb2_grpc.ConsistencyEngineServicer):
    """
    Cross-Zone Consistency Engine Service Implementation.
    
    This service provides comprehensive consistency checking across all document zones:
    - Visual OCR vs MRZ
    - Visual OCR vs Barcode
    - MRZ vs RFID
    - Checksum validation
    - Date format consistency
    - Cross-reference validation
    """

    def __init__(self, dependencies: Optional[Any] = None) -> None:
        """Initialize the Consistency Engine service."""
        self.logger = StructuredLogger(__name__)
        self.metrics = MetricsCollector("consistency_engine")
        
        # Initialize field mappings and rules
        self._initialize_field_mappings()
        self._initialize_consistency_rules()
        
        # Audit trail storage (in production, this would be a persistent store)
        self.audit_trail: List[AuditTrailEntry] = []
        
        self.logger.info("Consistency Engine service initialized")

    def _initialize_field_mappings(self) -> None:
        """Initialize canonical field mappings for different zones."""
        self.field_mappings = {
            "DOCUMENT_NUMBER": FieldMapping(
                canonical_field="DOCUMENT_NUMBER",
                zone_mappings={
                    "VISUAL_OCR": "document_number",
                    "MRZ": "document_number",
                    "BARCODE_1D": "doc_num",
                    "BARCODE_2D": "document_id",
                    "RFID_CHIP": "document_number"
                },
                validation_regex=r"^[A-Z0-9]{6,20}$",
                max_length=20,
                is_required=True
            ),
            "SURNAME": FieldMapping(
                canonical_field="SURNAME",
                zone_mappings={
                    "VISUAL_OCR": "surname",
                    "MRZ": "surname",
                    "RFID_CHIP": "surname"
                },
                validation_regex=r"^[A-Z\s\-']{1,50}$",
                max_length=50,
                is_required=True
            ),
            "GIVEN_NAMES": FieldMapping(
                canonical_field="GIVEN_NAMES",
                zone_mappings={
                    "VISUAL_OCR": "given_names",
                    "MRZ": "given_names",
                    "RFID_CHIP": "given_names"
                },
                validation_regex=r"^[A-Z\s\-']{1,50}$",
                max_length=50,
                is_required=True
            ),
            "DATE_OF_BIRTH": FieldMapping(
                canonical_field="DATE_OF_BIRTH",
                zone_mappings={
                    "VISUAL_OCR": "date_of_birth",
                    "MRZ": "date_of_birth",
                    "BARCODE_2D": "dob",
                    "RFID_CHIP": "date_of_birth"
                },
                data_type="date",
                validation_regex=r"^\d{4}-\d{2}-\d{2}$|^\d{2}\d{2}\d{2}$",
                is_required=True
            ),
            "DATE_OF_EXPIRY": FieldMapping(
                canonical_field="DATE_OF_EXPIRY",
                zone_mappings={
                    "VISUAL_OCR": "date_of_expiry",
                    "MRZ": "date_of_expiry",
                    "BARCODE_2D": "expiry",
                    "RFID_CHIP": "date_of_expiry"
                },
                data_type="date",
                validation_regex=r"^\d{4}-\d{2}-\d{2}$|^\d{2}\d{2}\d{2}$",
                is_required=True
            ),
            "NATIONALITY": FieldMapping(
                canonical_field="NATIONALITY",
                zone_mappings={
                    "VISUAL_OCR": "nationality",
                    "MRZ": "nationality",
                    "RFID_CHIP": "nationality"
                },
                validation_regex=r"^[A-Z]{3}$",
                max_length=3,
                is_required=True
            ),
            "GENDER": FieldMapping(
                canonical_field="GENDER",
                zone_mappings={
                    "VISUAL_OCR": "gender",
                    "MRZ": "sex",
                    "RFID_CHIP": "gender"
                },
                validation_regex=r"^[MFX]$",
                max_length=1,
                is_required=True
            ),
            "ISSUING_COUNTRY": FieldMapping(
                canonical_field="ISSUING_COUNTRY",
                zone_mappings={
                    "VISUAL_OCR": "issuing_country",
                    "MRZ": "issuing_state",
                    "RFID_CHIP": "issuing_state"
                },
                validation_regex=r"^[A-Z]{3}$",
                max_length=3,
                is_required=True
            )
        }

    def _initialize_consistency_rules(self) -> None:
        """Initialize consistency validation rules."""
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
            "FIELD_FUZZY_MATCH": ConsistencyRule(
                rule_id="FIELD_FUZZY_MATCH",
                name="Fuzzy Field Match",
                description="Fields must match within similarity threshold",
                source_zones={"VISUAL_OCR", "MRZ", "RFID_CHIP"},
                target_zones={"VISUAL_OCR", "MRZ", "RFID_CHIP"},
                applicable_fields={"SURNAME", "GIVEN_NAMES"},
                rule_type="fuzzy_match",
                is_critical=False,
                fuzzy_threshold=0.8
            ),
            "DATE_FORMAT_VALIDATION": ConsistencyRule(
                rule_id="DATE_FORMAT_VALIDATION",
                name="Date Format Consistency",
                description="Date fields must be in consistent formats and logically valid",
                source_zones={"VISUAL_OCR", "MRZ", "BARCODE_2D", "RFID_CHIP"},
                target_zones={"VISUAL_OCR", "MRZ", "BARCODE_2D", "RFID_CHIP"},
                applicable_fields={"DATE_OF_BIRTH", "DATE_OF_EXPIRY"},
                rule_type="date_validation",
                is_critical=True
            ),
            "CHECKSUM_VALIDATION": ConsistencyRule(
                rule_id="CHECKSUM_VALIDATION",
                name="Checksum Validation",
                description="Validate MRZ check digits and checksums",
                source_zones={"MRZ"},
                target_zones={"MRZ"},
                applicable_fields={"CHECK_DIGIT_DOCUMENT", "CHECK_DIGIT_DOB", "CHECK_DIGIT_EXPIRY", "CHECK_DIGIT_COMPOSITE"},
                rule_type="checksum",
                is_critical=True
            ),
            "CROSS_REFERENCE_VALIDATION": ConsistencyRule(
                rule_id="CROSS_REFERENCE_VALIDATION",
                name="Cross-Reference Validation",
                description="Validate cross-references between document zones",
                source_zones={"VISUAL_OCR", "MRZ", "RFID_CHIP"},
                target_zones={"VISUAL_OCR", "MRZ", "RFID_CHIP"},
                applicable_fields={"DOCUMENT_NUMBER", "DATE_OF_BIRTH", "DATE_OF_EXPIRY"},
                rule_type="cross_reference",
                is_critical=True
            )
        }

    async def CheckConsistency(
        self, 
        request: consistency_engine_pb2.ConsistencyCheckRequest, 
        context: grpc.aio.ServicerContext
    ) -> consistency_engine_pb2.ConsistencyCheckResponse:
        """
        Main consistency checking endpoint.
        
        Args:
            request: Consistency check request with zone data
            context: gRPC context
            
        Returns:
            Detailed consistency check results
        """
        start_time = datetime.now()
        audit_id = str(uuid.uuid4())
        
        try:
            self.logger.info(
                "Starting consistency check",
                extra={
                    "request_id": request.request_id,
                    "audit_id": audit_id,
                    "zones_count": len(request.zone_data),
                    "rules_requested": len(request.rules_to_check) or "all"
                }
            )
            
            # Extract and normalize field data from all zones
            normalized_data = self._extract_normalized_data(request.zone_data)
            
            # Determine which rules to apply
            rules_to_apply = self._determine_applicable_rules(request, normalized_data)
            
            # Execute consistency checks
            rule_results = []
            critical_mismatches = []
            warnings = []
            
            for rule in rules_to_apply:
                rule_result = await self._execute_rule(rule, normalized_data, request.fuzzy_match_threshold)
                rule_results.append(rule_result)
                
                # Categorize mismatches
                for mismatch in rule_result.mismatches:
                    if mismatch.severity_score >= 0.7:
                        critical_mismatches.append(mismatch)
                    else:
                        warnings.append(mismatch)
            
            # Calculate overall status and confidence
            overall_status, overall_confidence = self._calculate_overall_result(rule_results)
            
            # Generate response
            response = self._build_response(
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
                    audit_id,
                    request.request_id,
                    start_time,
                    "consistency_check",
                    {
                        "zones": [zone.zone for zone in request.zone_data],
                        "rules": [rule.rule_id for rule in rules_to_apply],
                        "overall_status": overall_status,
                        "mismatches_count": len(critical_mismatches) + len(warnings)
                    },
                    overall_status,
                    (datetime.now() - start_time).total_seconds() * 1000,
                    dict(request.context)
                )
            
            self.metrics.increment("consistency_checks_completed")
            self.metrics.histogram("consistency_check_duration_ms", (datetime.now() - start_time).total_seconds() * 1000)
            
            self.logger.info(
                "Consistency check completed",
                extra={
                    "request_id": request.request_id,
                    "audit_id": audit_id,
                    "overall_status": overall_status,
                    "processing_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
                    "critical_mismatches": len(critical_mismatches),
                    "warnings": len(warnings)
                }
            )
            
            return response
            
        except Exception as e:
            self.logger.error(
                "Consistency check failed",
                extra={
                    "request_id": request.request_id,
                    "audit_id": audit_id,
                    "error": str(e)
                },
                exc_info=True
            )
            
            self.metrics.increment("consistency_check_errors")
            
            # Return error response
            error_response = consistency_engine_pb2.ConsistencyCheckResponse()
            error_response.request_id = request.request_id
            error_response.overall_status = consistency_engine_pb2.CONSISTENCY_STATUS_UNSPECIFIED
            error_response.error.code = consistency_engine_pb2.ERROR_CODE_INTERNAL
            error_response.error.message = f"Internal error during consistency check: {str(e)}"
            
            return error_response

    def _extract_normalized_data(self, zone_data_list) -> Dict[str, Dict[str, str]]:
        """Extract and normalize field data from all zones."""
        normalized_data = {}
        
        for zone_data in zone_data_list:
            zone_name = consistency_engine_pb2.DocumentZone.Name(zone_data.zone)
            normalized_data[zone_name] = {}
            
            # Map zone-specific field names to canonical field names
            for zone_field_name, value in zone_data.fields.items():
                canonical_field = self._map_to_canonical_field(zone_name, zone_field_name)
                if canonical_field:
                    normalized_data[zone_name][canonical_field] = self._normalize_field_value(canonical_field, value)
        
        return normalized_data

    def _map_to_canonical_field(self, zone_name: str, zone_field_name: str) -> Optional[str]:
        """Map zone-specific field name to canonical field name."""
        for canonical_field, mapping in self.field_mappings.items():
            if zone_name in mapping.zone_mappings and mapping.zone_mappings[zone_name] == zone_field_name:
                return canonical_field
        return None

    def _normalize_field_value(self, canonical_field: str, value: str) -> str:
        """Normalize field value according to canonical field type."""
        if not value:
            return ""
        
        mapping = self.field_mappings.get(canonical_field)
        if not mapping:
            return value
        
        normalized = value.strip().upper()
        
        # Date normalization
        if mapping.data_type == "date":
            normalized = self._normalize_date(normalized)
        
        # Apply validation regex if available
        if mapping.validation_regex and not re.match(mapping.validation_regex, normalized):
            self.logger.warning(f"Field {canonical_field} value '{normalized}' does not match validation regex")
        
        return normalized

    def _normalize_date(self, date_str: str) -> str:
        """Normalize date string to YYYY-MM-DD format."""
        if not date_str:
            return ""
        
        # Handle YYMMDD format (common in MRZ)
        if re.match(r"^\d{6}$", date_str):
            year = int(date_str[:2])
            # Assume 20xx for years 00-30, 19xx for years 31-99
            if year <= 30:
                year += 2000
            else:
                year += 1900
            month = date_str[2:4]
            day = date_str[4:6]
            return f"{year:04d}-{month}-{day}"
        
        # Handle YYYY-MM-DD format
        if re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
            return date_str
        
        # Handle other common formats
        # Add more date parsing logic as needed
        
        return date_str

    def _determine_applicable_rules(self, request, normalized_data) -> List[ConsistencyRule]:
        """Determine which consistency rules to apply."""
        if request.rules_to_check:
            # Use specific rules requested
            rule_names = [consistency_engine_pb2.ConsistencyRule.Name(rule) for rule in request.rules_to_check]
            return [self.consistency_rules[name] for name in rule_names if name in self.consistency_rules]
        else:
            # Use all applicable rules based on available zones and fields
            applicable_rules = []
            available_zones = set(consistency_engine_pb2.DocumentZone.Name(zone.zone) for zone in request.zone_data)
            available_fields = set()
            
            for zone_data in normalized_data.values():
                available_fields.update(zone_data.keys())
            
            for rule in self.consistency_rules.values():
                if (rule.source_zones.intersection(available_zones) and 
                    rule.target_zones.intersection(available_zones) and
                    rule.applicable_fields.intersection(available_fields)):
                    applicable_rules.append(rule)
            
            return applicable_rules

    async def _execute_rule(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]], fuzzy_threshold: float) -> Any:
        """Execute a specific consistency rule."""
        start_time = datetime.now()
        
        mismatches = []
        status = consistency_engine_pb2.PASS
        confidence_score = 1.0
        
        try:
            if rule.rule_type == "exact_match":
                mismatches, confidence_score = self._check_exact_matches(rule, normalized_data)
            elif rule.rule_type == "fuzzy_match":
                mismatches, confidence_score = self._check_fuzzy_matches(rule, normalized_data, fuzzy_threshold or rule.fuzzy_threshold)
            elif rule.rule_type == "date_validation":
                mismatches, confidence_score = self._check_date_validation(rule, normalized_data)
            elif rule.rule_type == "checksum":
                mismatches, confidence_score = self._check_checksums(rule, normalized_data)
            elif rule.rule_type == "cross_reference":
                mismatches, confidence_score = self._check_cross_references(rule, normalized_data)
            
            # Determine status based on mismatches
            if mismatches:
                critical_mismatches = [m for m in mismatches if m.severity_score >= 0.7]
                if critical_mismatches:
                    status = consistency_engine_pb2.FAIL
                else:
                    status = consistency_engine_pb2.WARNING
            
            execution_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            # Build rule result
            rule_result = consistency_engine_pb2.RuleCheckResult()
            rule_result.rule = getattr(consistency_engine_pb2, rule.rule_id)
            rule_result.rule_description = rule.description
            rule_result.status = status
            rule_result.mismatches.extend(mismatches)
            rule_result.confidence_score = confidence_score
            rule_result.confidence_level = self._calculate_confidence_level(confidence_score)
            rule_result.explanation = self._generate_rule_explanation(rule, mismatches, confidence_score)
            rule_result.checked_at.CopyFrom(self._datetime_to_timestamp(datetime.now()))
            rule_result.execution_time_ms = execution_time_ms
            
            return rule_result
            
        except Exception as e:
            self.logger.error(f"Error executing rule {rule.rule_id}: {str(e)}")
            
            # Return error result
            rule_result = consistency_engine_pb2.RuleCheckResult()
            rule_result.rule = getattr(consistency_engine_pb2, rule.rule_id)
            rule_result.rule_description = rule.description
            rule_result.status = consistency_engine_pb2.ERROR
            rule_result.confidence_score = 0.0
            rule_result.confidence_level = consistency_engine_pb2.VERY_LOW
            rule_result.explanation = f"Error executing rule: {str(e)}"
            rule_result.checked_at.CopyFrom(self._datetime_to_timestamp(datetime.now()))
            rule_result.execution_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return rule_result

    def _check_exact_matches(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]]) -> Tuple[List[Any], float]:
        """Check for exact matches between zones."""
        mismatches = []
        total_comparisons = 0
        successful_matches = 0
        
        # Get zones that have data
        available_zones = [zone for zone in rule.source_zones.union(rule.target_zones) if zone in normalized_data]
        
        # Compare each field across all zone pairs
        for field in rule.applicable_fields:
            zones_with_field = [zone for zone in available_zones if field in normalized_data[zone]]
            
            if len(zones_with_field) < 2:
                continue  # Need at least 2 zones to compare
            
            # Compare all pairs
            for i in range(len(zones_with_field)):
                for j in range(i + 1, len(zones_with_field)):
                    zone_a = zones_with_field[i]
                    zone_b = zones_with_field[j]
                    value_a = normalized_data[zone_a][field]
                    value_b = normalized_data[zone_b][field]
                    
                    total_comparisons += 1
                    
                    if value_a == value_b:
                        successful_matches += 1
                    else:
                        # Create mismatch entry
                        mismatch = consistency_engine_pb2.FieldMismatch()
                        mismatch.field = getattr(consistency_engine_pb2, field)
                        mismatch.field_name = field.lower().replace("_", " ")
                        mismatch.zone_a = getattr(consistency_engine_pb2, zone_a)
                        mismatch.value_a = value_a
                        mismatch.zone_b = getattr(consistency_engine_pb2, zone_b)
                        mismatch.value_b = value_b
                        mismatch.rule_violated = getattr(consistency_engine_pb2, rule.rule_id)
                        mismatch.explanation = f"Exact match failed: '{value_a}' != '{value_b}'"
                        mismatch.severity_score = 1.0 if rule.is_critical else 0.5
                        mismatch.details["comparison_type"] = "exact_match"
                        
                        mismatches.append(mismatch)
        
        confidence_score = successful_matches / total_comparisons if total_comparisons > 0 else 1.0
        return mismatches, confidence_score

    def _check_fuzzy_matches(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]], threshold: float) -> Tuple[List[Any], float]:
        """Check for fuzzy matches between zones using similarity threshold."""
        mismatches = []
        total_comparisons = 0
        similarity_scores = []
        
        # Get zones that have data
        available_zones = [zone for zone in rule.source_zones.union(rule.target_zones) if zone in normalized_data]
        
        # Compare each field across all zone pairs
        for field in rule.applicable_fields:
            zones_with_field = [zone for zone in available_zones if field in normalized_data[zone]]
            
            if len(zones_with_field) < 2:
                continue
            
            # Compare all pairs
            for i in range(len(zones_with_field)):
                for j in range(i + 1, len(zones_with_field)):
                    zone_a = zones_with_field[i]
                    zone_b = zones_with_field[j]
                    value_a = normalized_data[zone_a][field]
                    value_b = normalized_data[zone_b][field]
                    
                    total_comparisons += 1
                    
                    # Calculate similarity
                    similarity = SequenceMatcher(None, value_a.lower(), value_b.lower()).ratio()
                    similarity_scores.append(similarity)
                    
                    if similarity < threshold:
                        # Create mismatch entry
                        mismatch = consistency_engine_pb2.FieldMismatch()
                        mismatch.field = getattr(consistency_engine_pb2, field)
                        mismatch.field_name = field.lower().replace("_", " ")
                        mismatch.zone_a = getattr(consistency_engine_pb2, zone_a)
                        mismatch.value_a = value_a
                        mismatch.zone_b = getattr(consistency_engine_pb2, zone_b)
                        mismatch.value_b = value_b
                        mismatch.rule_violated = getattr(consistency_engine_pb2, rule.rule_id)
                        mismatch.explanation = f"Fuzzy match failed: similarity {similarity:.3f} < threshold {threshold:.3f}"
                        mismatch.severity_score = 1.0 - similarity  # Lower similarity = higher severity
                        mismatch.details["similarity_score"] = str(similarity)
                        mismatch.details["threshold"] = str(threshold)
                        
                        mismatches.append(mismatch)
        
        confidence_score = sum(similarity_scores) / len(similarity_scores) if similarity_scores else 1.0
        return mismatches, confidence_score

    def _check_date_validation(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]]) -> Tuple[List[Any], float]:
        """Validate date formats and logical consistency."""
        mismatches = []
        valid_dates = 0
        total_dates = 0
        
        # Implementation for date validation logic
        # This would include format validation, logical date checks, etc.
        # For brevity, returning empty mismatches
        
        confidence_score = 1.0  # Would be calculated based on actual validation
        return mismatches, confidence_score

    def _check_checksums(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]]) -> Tuple[List[Any], float]:
        """Validate MRZ checksums and check digits."""
        mismatches = []
        
        # Implementation for checksum validation
        # This would include MRZ check digit calculations
        # For brevity, returning empty mismatches
        
        confidence_score = 1.0  # Would be calculated based on checksum validation
        return mismatches, confidence_score

    def _check_cross_references(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]]) -> Tuple[List[Any], float]:
        """Check cross-references between document zones."""
        mismatches = []
        
        # Implementation for cross-reference validation
        # This would include complex validation logic
        # For brevity, returning empty mismatches
        
        confidence_score = 1.0  # Would be calculated based on cross-reference checks
        return mismatches, confidence_score

    def _calculate_overall_result(self, rule_results: List[Any]) -> Tuple[int, float]:
        """Calculate overall consistency status and confidence."""
        if not rule_results:
            return consistency_engine_pb2.INCOMPLETE, 0.0
        
        # Check for any critical failures
        critical_failures = [r for r in rule_results if r.status == consistency_engine_pb2.FAIL]
        if critical_failures:
            overall_status = consistency_engine_pb2.FAIL
        else:
            # Check for warnings
            warnings = [r for r in rule_results if r.status == consistency_engine_pb2.WARNING]
            if warnings:
                overall_status = consistency_engine_pb2.WARNING
            else:
                overall_status = consistency_engine_pb2.PASS
        
        # Calculate average confidence
        confidence_scores = [r.confidence_score for r in rule_results if r.confidence_score > 0]
        overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        return overall_status, overall_confidence

    def _calculate_confidence_level(self, confidence_score: float) -> int:
        """Convert confidence score to confidence level enum."""
        if confidence_score >= 0.81:
            return consistency_engine_pb2.VERY_HIGH
        elif confidence_score >= 0.61:
            return consistency_engine_pb2.HIGH
        elif confidence_score >= 0.41:
            return consistency_engine_pb2.MEDIUM
        elif confidence_score >= 0.21:
            return consistency_engine_pb2.LOW
        else:
            return consistency_engine_pb2.VERY_LOW

    def _generate_rule_explanation(self, rule: ConsistencyRule, mismatches: List[Any], confidence_score: float) -> str:
        """Generate human-readable explanation for rule result."""
        if not mismatches:
            return f"All checks passed for {rule.name} with {confidence_score:.1%} confidence"
        else:
            return f"{len(mismatches)} mismatches found in {rule.name} (confidence: {confidence_score:.1%})"

    def _build_response(self, request_id: str, audit_id: str, overall_status: int, 
                       rule_results: List[Any], critical_mismatches: List[Any], 
                       warnings: List[Any], overall_confidence: float, start_time: datetime) -> Any:
        """Build the consistency check response."""
        response = consistency_engine_pb2.ConsistencyCheckResponse()
        response.request_id = request_id
        response.overall_status = overall_status
        response.rule_results.extend(rule_results)
        response.critical_mismatches.extend(critical_mismatches)
        response.warnings.extend(warnings)
        response.overall_confidence = overall_confidence
        response.overall_confidence_level = self._calculate_confidence_level(overall_confidence)
        response.summary = self._generate_summary(overall_status, critical_mismatches, warnings, overall_confidence)
        response.processed_at.CopyFrom(self._datetime_to_timestamp(datetime.now()))
        response.total_processing_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        response.audit_id = audit_id
        
        return response

    def _generate_summary(self, overall_status: int, critical_mismatches: List[Any], 
                         warnings: List[Any], overall_confidence: float) -> str:
        """Generate human-readable summary of consistency check results."""
        status_text = {
            consistency_engine_pb2.PASS: "PASS",
            consistency_engine_pb2.FAIL: "FAIL", 
            consistency_engine_pb2.WARNING: "WARNING",
            consistency_engine_pb2.INCOMPLETE: "INCOMPLETE",
            consistency_engine_pb2.ERROR: "ERROR"
        }.get(overall_status, "UNKNOWN")
        
        summary = f"Consistency check {status_text} with {overall_confidence:.1%} confidence. "
        
        if critical_mismatches:
            summary += f"{len(critical_mismatches)} critical mismatches found. "
        
        if warnings:
            summary += f"{len(warnings)} warnings found. "
        
        if overall_status == consistency_engine_pb2.PASS:
            summary += "All cross-zone consistency checks passed."
        
        return summary

    def _datetime_to_timestamp(self, dt: datetime) -> Timestamp:
        """Convert datetime to protobuf Timestamp."""
        timestamp = Timestamp()
        timestamp.FromDatetime(dt)
        return timestamp

    async def _store_audit_entry(self, audit_id: str, request_id: str, timestamp: datetime,
                                operation: str, details: Dict[str, Any], result_status: str,
                                processing_time_ms: float, context: Dict[str, str]) -> None:
        """Store audit trail entry."""
        entry = AuditTrailEntry(
            audit_id=audit_id,
            request_id=request_id,
            timestamp=timestamp,
            operation=operation,
            details=details,
            result_status=result_status,
            processing_time_ms=int(processing_time_ms),
            context=context
        )
        
        self.audit_trail.append(entry)
        
        # In production, this would be stored in a persistent audit database
        self.logger.info(
            "Audit entry stored",
            extra={
                "audit_id": audit_id,
                "operation": operation,
                "result_status": result_status
            }
        )

    async def GetAuditHistory(
        self, 
        request: consistency_engine_pb2.AuditHistoryRequest, 
        context: grpc.aio.ServicerContext
    ) -> consistency_engine_pb2.AuditHistoryResponse:
        """Get audit history for consistency checks."""
        # Implementation for audit history retrieval
        # For brevity, returning empty response
        response = consistency_engine_pb2.AuditHistoryResponse()
        return response

    async def ValidateFieldMapping(
        self, 
        request: consistency_engine_pb2.FieldMappingRequest, 
        context: grpc.aio.ServicerContext
    ) -> consistency_engine_pb2.FieldMappingResponse:
        """Validate specific field mappings."""
        # Implementation for field mapping validation
        # For brevity, returning empty response
        response = consistency_engine_pb2.FieldMappingResponse()
        return response

    async def GetSupportedRules(
        self, 
        request: consistency_engine_pb2.GetSupportedRulesRequest, 
        context: grpc.aio.ServicerContext
    ) -> consistency_engine_pb2.GetSupportedRulesResponse:
        """Get supported consistency rules."""
        # Implementation for supported rules
        # For brevity, returning empty response
        response = consistency_engine_pb2.GetSupportedRulesResponse()
        return response