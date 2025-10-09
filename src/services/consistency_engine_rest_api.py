from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

import grpc
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from google.protobuf.json_format import MessageToDict, ParseDict
from google.protobuf.timestamp_pb2 import Timestamp
from pydantic import BaseModel, Field, validator

from src.marty_common.observability import MetricsCollector, StructuredLogger
from src.proto import consistency_engine_pb2, consistency_engine_pb2_grpc
from src.services.consistency_engine import ConsistencyEngine

# Pydantic models for REST API


class ZoneFieldDataModel(BaseModel):
    """Zone field data for REST API."""

    zone: str = Field(..., description="Document zone identifier")
    fields: dict[str, str] = Field(..., description="Extracted field values")
    extraction_confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Extraction confidence score"
    )
    extraction_method: str | None = Field(None, description="Method used for extraction")
    metadata: dict[str, str] = Field(default_factory=dict, description="Additional metadata")

    @validator("zone")
    def validate_zone(cls, v):
        """Validate zone is a recognized document zone."""
        valid_zones = {
            "VISUAL_OCR",
            "MRZ",
            "BARCODE_1D",
            "BARCODE_2D",
            "RFID_CHIP",
            "MAGNETIC_STRIPE",
        }
        if v not in valid_zones:
            raise ValueError(f"Invalid zone: {v}. Must be one of {valid_zones}")
        return v


class ConsistencyCheckRequestModel(BaseModel):
    """Consistency check request for REST API."""

    request_id: str | None = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique request identifier"
    )
    zone_data: list[ZoneFieldDataModel] = Field(
        ..., description="Data extracted from document zones"
    )
    rules_to_check: list[str] = Field(
        default_factory=list, description="Specific rules to check (empty = all applicable)"
    )
    include_audit_trail: bool = Field(default=True, description="Whether to store audit trail")
    context: dict[str, str] = Field(default_factory=dict, description="Additional context")
    fuzzy_match_threshold: float = Field(
        default=0.8, ge=0.0, le=1.0, description="Threshold for fuzzy matching"
    )

    @validator("rules_to_check")
    def validate_rules(cls, v):
        """Validate rule names."""
        valid_rules = {
            "FIELD_EXACT_MATCH",
            "FIELD_FUZZY_MATCH",
            "DATE_FORMAT_VALIDATION",
            "CHECKSUM_VALIDATION",
            "CROSS_REFERENCE_VALIDATION",
        }
        for rule in v:
            if rule not in valid_rules:
                raise ValueError(f"Invalid rule: {rule}. Must be one of {valid_rules}")
        return v


class FieldMismatchModel(BaseModel):
    """Field mismatch model for REST API."""

    field: str = Field(..., description="Canonical field name")
    field_name: str = Field(..., description="Human-readable field name")
    zone_a: str = Field(..., description="First zone")
    value_a: str = Field(..., description="Value from first zone")
    zone_b: str = Field(..., description="Second zone")
    value_b: str = Field(..., description="Value from second zone")
    rule_violated: str = Field(..., description="Rule that was violated")
    explanation: str = Field(..., description="Explanation of the mismatch")
    severity_score: float = Field(..., ge=0.0, le=1.0, description="Severity score")
    details: dict[str, str] = Field(default_factory=dict, description="Additional details")


class RuleCheckResultModel(BaseModel):
    """Rule check result model for REST API."""

    rule: str = Field(..., description="Rule identifier")
    rule_description: str = Field(..., description="Rule description")
    status: str = Field(..., description="Check status")
    mismatches: list[FieldMismatchModel] = Field(
        default_factory=list, description="Field mismatches found"
    )
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    confidence_level: str = Field(..., description="Confidence level")
    explanation: str = Field(..., description="Rule execution explanation")
    checked_at: str = Field(..., description="Timestamp when checked")
    execution_time_ms: int = Field(..., description="Execution time in milliseconds")


class ConsistencyCheckResponseModel(BaseModel):
    """Consistency check response for REST API."""

    request_id: str = Field(..., description="Request identifier")
    overall_status: str = Field(..., description="Overall consistency status")
    rule_results: list[RuleCheckResultModel] = Field(
        default_factory=list, description="Individual rule results"
    )
    critical_mismatches: list[FieldMismatchModel] = Field(
        default_factory=list, description="Critical mismatches"
    )
    warnings: list[FieldMismatchModel] = Field(
        default_factory=list, description="Warning-level mismatches"
    )
    overall_confidence: float = Field(..., ge=0.0, le=1.0, description="Overall confidence")
    overall_confidence_level: str = Field(..., description="Overall confidence level")
    summary: str = Field(..., description="Human-readable summary")
    processed_at: str = Field(..., description="Processing timestamp")
    total_processing_time_ms: int = Field(..., description="Total processing time")
    audit_id: str = Field(..., description="Audit trail identifier")
    metadata: dict[str, str] = Field(default_factory=dict, description="Additional metadata")


class AuditHistoryRequestModel(BaseModel):
    """Audit history request for REST API."""

    audit_id: str | None = Field(None, description="Specific audit record ID")
    request_id: str | None = Field(None, description="Request ID filter")
    from_time: str | None = Field(None, description="Start time filter (ISO format)")
    to_time: str | None = Field(None, description="End time filter (ISO format)")
    limit: int = Field(default=100, ge=1, le=1000, description="Maximum records to return")
    offset: int = Field(default=0, ge=0, description="Pagination offset")


class FieldMappingRequestModel(BaseModel):
    """Field mapping validation request for REST API."""

    source_zone: str = Field(..., description="Source zone")
    target_zone: str = Field(..., description="Target zone")
    field: str = Field(..., description="Canonical field name")
    source_value: str = Field(..., description="Value from source zone")
    target_value: str = Field(..., description="Value from target zone")
    rule: str = Field(..., description="Consistency rule to apply")


class FieldMappingResponseModel(BaseModel):
    """Field mapping validation response for REST API."""

    is_consistent: bool = Field(..., description="Whether mapping is consistent")
    consistency_score: float = Field(..., ge=0.0, le=1.0, description="Consistency score")
    explanation: str = Field(..., description="Explanation of the result")
    suggestions: list[str] = Field(default_factory=list, description="Suggested corrections")


class RuleDescriptionModel(BaseModel):
    """Rule description model for REST API."""

    rule: str = Field(..., description="Rule identifier")
    name: str = Field(..., description="Rule name")
    description: str = Field(..., description="Rule description")
    applicable_zones: list[str] = Field(default_factory=list, description="Applicable zones")
    applicable_fields: list[str] = Field(default_factory=list, description="Applicable fields")
    is_critical: bool = Field(..., description="Whether rule failure is critical")
    documentation_url: str | None = Field(None, description="Documentation URL")


class GetSupportedRulesResponseModel(BaseModel):
    """Supported rules response for REST API."""

    rules: list[RuleDescriptionModel] = Field(default_factory=list, description="Available rules")
    total_rules: int = Field(..., description="Total number of rules")


class ConsistencyEngineRESTAPI:
    """
    REST API wrapper for the Consistency Engine gRPC service.

    Provides HTTP endpoints that wrap the gRPC service for easier
    integration and testing.
    """

    def __init__(self, grpc_service: ConsistencyEngine | None = None) -> None:
        """Initialize REST API wrapper."""
        self.logger = StructuredLogger(__name__)
        self.metrics = MetricsCollector("consistency_engine_rest")

        # Initialize gRPC service or create new instance
        self.grpc_service = grpc_service or ConsistencyEngine()

        # Create FastAPI app
        self.app = FastAPI(
            title="Cross-Zone Consistency Engine API",
            description="REST API for cross-zone consistency checking in document verification",
            version="1.0.0",
            docs_url="/docs",
            redoc_url="/redoc",
        )

        # Add middleware
        self._setup_middleware()

        # Add routes
        self._setup_routes()

        self.logger.info("Consistency Engine REST API initialized")

    def _setup_middleware(self) -> None:
        """Set up FastAPI middleware."""
        # CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Request logging middleware
        @self.app.middleware("http")
        async def log_requests(request: Request, call_next):
            start_time = datetime.now()

            # Log request
            self.logger.info(
                "Request received",
                extra={
                    "method": request.method,
                    "url": str(request.url),
                    "client_ip": request.client.host if request.client else None,
                    "user_agent": request.headers.get("user-agent"),
                },
            )

            # Process request
            response = await call_next(request)

            # Log response
            processing_time = (datetime.now() - start_time).total_seconds() * 1000

            self.logger.info(
                "Request completed",
                extra={
                    "method": request.method,
                    "url": str(request.url),
                    "status_code": response.status_code,
                    "processing_time_ms": processing_time,
                },
            )

            # Record metrics
            self.metrics.histogram(
                "http_request_duration_ms",
                processing_time,
                {
                    "method": request.method,
                    "endpoint": request.url.path,
                    "status_code": str(response.status_code),
                },
            )

            self.metrics.increment(
                "http_requests_total",
                {
                    "method": request.method,
                    "endpoint": request.url.path,
                    "status_code": str(response.status_code),
                },
            )

            return response

    def _setup_routes(self) -> None:
        """Set up FastAPI routes."""

        @self.app.get("/health", summary="Health check")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "service": "consistency-engine",
                "timestamp": datetime.now().isoformat(),
            }

        @self.app.get("/metrics", summary="Metrics summary")
        async def get_metrics():
            """Get metrics summary."""
            return self.metrics.get_metric_summary()

        @self.app.post(
            "/api/v1/consistency/check",
            response_model=ConsistencyCheckResponseModel,
            summary="Perform consistency check",
            description="Perform comprehensive consistency checks across document zones",
        )
        async def check_consistency(request: ConsistencyCheckRequestModel):
            """Main consistency checking endpoint."""
            try:
                # Convert REST request to gRPC request
                grpc_request = self._rest_to_grpc_consistency_request(request)

                # Call gRPC service
                grpc_response = await self.grpc_service.CheckConsistency(grpc_request, None)

                # Convert gRPC response to REST response
                rest_response = self._grpc_to_rest_consistency_response(grpc_response)

                self.metrics.increment("consistency_checks_completed")

                return rest_response

            except Exception as e:
                self.logger.error(f"Consistency check failed: {str(e)}", exc_info=True)
                self.metrics.increment("consistency_check_errors")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Consistency check failed: {str(e)}",
                )

        @self.app.get(
            "/api/v1/consistency/audit/{audit_id}",
            summary="Get audit history",
            description="Retrieve audit history for consistency checks",
        )
        async def get_audit_history(audit_id: str, request: AuditHistoryRequestModel = None):
            """Get audit history endpoint."""
            try:
                # Convert to gRPC request
                grpc_request = consistency_engine_pb2.AuditHistoryRequest()
                grpc_request.audit_id = audit_id
                if request:
                    if request.request_id:
                        grpc_request.request_id = request.request_id
                    if request.from_time:
                        # Parse ISO timestamp and convert to protobuf Timestamp
                        # Implementation would parse ISO string to timestamp
                        pass
                    grpc_request.limit = request.limit
                    grpc_request.offset = request.offset

                # Call gRPC service
                grpc_response = await self.grpc_service.GetAuditHistory(grpc_request, None)

                # Convert response
                response_dict = MessageToDict(grpc_response)

                return response_dict

            except Exception as e:
                self.logger.error(f"Audit history retrieval failed: {str(e)}", exc_info=True)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Audit history retrieval failed: {str(e)}",
                )

        @self.app.post(
            "/api/v1/consistency/validate-mapping",
            response_model=FieldMappingResponseModel,
            summary="Validate field mapping",
            description="Validate specific field mapping between zones",
        )
        async def validate_field_mapping(request: FieldMappingRequestModel):
            """Field mapping validation endpoint."""
            try:
                # Convert to gRPC request
                grpc_request = consistency_engine_pb2.FieldMappingRequest()
                grpc_request.source_zone = getattr(consistency_engine_pb2, request.source_zone)
                grpc_request.target_zone = getattr(consistency_engine_pb2, request.target_zone)
                grpc_request.field = getattr(consistency_engine_pb2, request.field)
                grpc_request.source_value = request.source_value
                grpc_request.target_value = request.target_value
                grpc_request.rule = getattr(consistency_engine_pb2, request.rule)

                # Call gRPC service
                grpc_response = await self.grpc_service.ValidateFieldMapping(grpc_request, None)

                # Convert response
                rest_response = FieldMappingResponseModel(
                    is_consistent=grpc_response.is_consistent,
                    consistency_score=grpc_response.consistency_score,
                    explanation=grpc_response.explanation,
                    suggestions=list(grpc_response.suggestions),
                )

                return rest_response

            except Exception as e:
                self.logger.error(f"Field mapping validation failed: {str(e)}", exc_info=True)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Field mapping validation failed: {str(e)}",
                )

        @self.app.get(
            "/api/v1/consistency/rules",
            response_model=GetSupportedRulesResponseModel,
            summary="Get supported rules",
            description="Get list of supported consistency rules",
        )
        async def get_supported_rules(
            zone_filter: str | None = None, field_filter: str | None = None
        ):
            """Get supported rules endpoint."""
            try:
                # Convert to gRPC request
                grpc_request = consistency_engine_pb2.GetSupportedRulesRequest()
                if zone_filter:
                    grpc_request.zone_filter = getattr(consistency_engine_pb2, zone_filter)
                if field_filter:
                    grpc_request.field_filter = getattr(consistency_engine_pb2, field_filter)

                # Call gRPC service
                grpc_response = await self.grpc_service.GetSupportedRules(grpc_request, None)

                # Convert response
                rules = []
                for rule in grpc_response.rules:
                    rule_model = RuleDescriptionModel(
                        rule=consistency_engine_pb2.ConsistencyRule.Name(rule.rule),
                        name=rule.name,
                        description=rule.description,
                        applicable_zones=[
                            consistency_engine_pb2.DocumentZone.Name(zone)
                            for zone in rule.applicable_zones
                        ],
                        applicable_fields=[
                            consistency_engine_pb2.CanonicalField.Name(field)
                            for field in rule.applicable_fields
                        ],
                        is_critical=rule.is_critical,
                        documentation_url=rule.documentation_url or None,
                    )
                    rules.append(rule_model)

                rest_response = GetSupportedRulesResponseModel(
                    rules=rules, total_rules=grpc_response.total_rules
                )

                return rest_response

            except Exception as e:
                self.logger.error(f"Get supported rules failed: {str(e)}", exc_info=True)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Get supported rules failed: {str(e)}",
                )

        # Add OpenAPI schema customization
        @self.app.get("/api/v1/schema", include_in_schema=False)
        async def get_openapi_schema():
            """Get OpenAPI schema."""
            return self.app.openapi()

    def _rest_to_grpc_consistency_request(
        self, rest_request: ConsistencyCheckRequestModel
    ) -> consistency_engine_pb2.ConsistencyCheckRequest:
        """Convert REST request to gRPC request."""
        grpc_request = consistency_engine_pb2.ConsistencyCheckRequest()
        grpc_request.request_id = rest_request.request_id
        grpc_request.include_audit_trail = rest_request.include_audit_trail
        grpc_request.fuzzy_match_threshold = rest_request.fuzzy_match_threshold

        # Convert zone data
        for zone_data in rest_request.zone_data:
            grpc_zone_data = consistency_engine_pb2.ZoneFieldData()
            grpc_zone_data.zone = getattr(consistency_engine_pb2, zone_data.zone)
            grpc_zone_data.fields.update(zone_data.fields)
            grpc_zone_data.extraction_confidence = zone_data.extraction_confidence
            grpc_zone_data.extraction_method = zone_data.extraction_method or ""
            grpc_zone_data.metadata.update(zone_data.metadata)
            grpc_zone_data.extracted_at.CopyFrom(self._datetime_to_timestamp(datetime.now()))

            grpc_request.zone_data.append(grpc_zone_data)

        # Convert rules
        for rule in rest_request.rules_to_check:
            grpc_request.rules_to_check.append(getattr(consistency_engine_pb2, rule))

        # Convert context
        grpc_request.context.update(rest_request.context)

        return grpc_request

    def _grpc_to_rest_consistency_response(
        self, grpc_response: consistency_engine_pb2.ConsistencyCheckResponse
    ) -> ConsistencyCheckResponseModel:
        """Convert gRPC response to REST response."""

        # Convert field mismatches
        def convert_mismatch(mismatch):
            return FieldMismatchModel(
                field=consistency_engine_pb2.CanonicalField.Name(mismatch.field),
                field_name=mismatch.field_name,
                zone_a=consistency_engine_pb2.DocumentZone.Name(mismatch.zone_a),
                value_a=mismatch.value_a,
                zone_b=consistency_engine_pb2.DocumentZone.Name(mismatch.zone_b),
                value_b=mismatch.value_b,
                rule_violated=consistency_engine_pb2.ConsistencyRule.Name(mismatch.rule_violated),
                explanation=mismatch.explanation,
                severity_score=mismatch.severity_score,
                details=dict(mismatch.details),
            )

        # Convert rule results
        rule_results = []
        for rule_result in grpc_response.rule_results:
            result_model = RuleCheckResultModel(
                rule=consistency_engine_pb2.ConsistencyRule.Name(rule_result.rule),
                rule_description=rule_result.rule_description,
                status=consistency_engine_pb2.ConsistencyStatus.Name(rule_result.status),
                mismatches=[convert_mismatch(m) for m in rule_result.mismatches],
                confidence_score=rule_result.confidence_score,
                confidence_level=consistency_engine_pb2.ConfidenceLevel.Name(
                    rule_result.confidence_level
                ),
                explanation=rule_result.explanation,
                checked_at=rule_result.checked_at.ToDatetime().isoformat(),
                execution_time_ms=rule_result.execution_time_ms,
            )
            rule_results.append(result_model)

        rest_response = ConsistencyCheckResponseModel(
            request_id=grpc_response.request_id,
            overall_status=consistency_engine_pb2.ConsistencyStatus.Name(
                grpc_response.overall_status
            ),
            rule_results=rule_results,
            critical_mismatches=[convert_mismatch(m) for m in grpc_response.critical_mismatches],
            warnings=[convert_mismatch(m) for m in grpc_response.warnings],
            overall_confidence=grpc_response.overall_confidence,
            overall_confidence_level=consistency_engine_pb2.ConfidenceLevel.Name(
                grpc_response.overall_confidence_level
            ),
            summary=grpc_response.summary,
            processed_at=grpc_response.processed_at.ToDatetime().isoformat(),
            total_processing_time_ms=grpc_response.total_processing_time_ms,
            audit_id=grpc_response.audit_id,
            metadata=dict(grpc_response.metadata),
        )

        return rest_response

    def _datetime_to_timestamp(self, dt: datetime) -> Timestamp:
        """Convert datetime to protobuf Timestamp."""
        timestamp = Timestamp()
        timestamp.FromDatetime(dt)
        return timestamp


# Factory function for creating the FastAPI app
def create_consistency_engine_app(grpc_service: ConsistencyEngine | None = None) -> FastAPI:
    """Create and configure the Consistency Engine FastAPI application."""
    api = ConsistencyEngineRESTAPI(grpc_service)
    return api.app


# CLI entry point for running the REST API server
if __name__ == "__main__":
    import uvicorn

    app = create_consistency_engine_app()
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info", access_log=True)
