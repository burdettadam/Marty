"""FastAPI application exposing the Marty operator UI."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import grpc
from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.proto import inspection_system_pb2, passport_engine_pb2

try:
    from src.proto import mdl_engine_pb2
except ImportError:  # pragma: no cover - mdl proto optional in some deployments
    mdl_engine_pb2 = None  # type: ignore

from .config import UiSettings, get_settings
from .grpc_clients import GrpcClientFactory
from .state import OperationRecord, operation_log

LOGGER = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

# Global cache for E2E testing - preserves results across requests
_result_cache = {"process_result": None, "inspection_result": None}


def create_app(settings: UiSettings | None = None) -> FastAPI:
    """Application factory used by both runtime and tests."""
    if settings is None:
        settings = get_settings()

    app = FastAPI(title=settings.title)
    templates = Jinja2Templates(directory="src/ui_app/templates")
    templates.env.globals["navigation"] = [
        {"path": "/", "label": "Dashboard"},
        {"path": "/passport", "label": "Passports"},
        {"path": "/mdl", "label": "Mobile DL"},
        {"path": "/csca", "label": "CSCA Service"},
        {"path": "/document-signer", "label": "Document Signer"},
        {"path": "/mdoc", "label": "mDoc Engine"},
        {"path": "/dtc", "label": "DTC Engine"},
        {"path": "/pkd", "label": "PKD Service"},
        {"path": "/trust-anchor", "label": "Trust Anchor"},
        {"path": "/admin", "label": "Administration"},
    ]

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def get_factory() -> GrpcClientFactory:
        return GrpcClientFactory(settings)

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        """Favicon endpoint to prevent 404 errors."""
        return {"message": "No favicon configured"}

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, Any]:
        """Lightweight health endpoint for readiness probes."""

        return {
            "status": "ok",
            "environment": settings.environment,
            "timestamp": datetime.utcnow().isoformat(),
        }

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        """Render overview dashboard."""

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "settings": settings,
                "operation_log": list(operation_log.items()),
                "summary": operation_log.summary(),
            },
        )

    @app.get("/passport", response_class=HTMLResponse)
    async def passport_console(request: Request):
        """Entry point for passport issuance and inspection."""

        return templates.TemplateResponse(
            "passport.html",
            {
                "request": request,
                "settings": settings,
                "process_result": None,
                "inspection_result": None,
            },
        )

    @app.post("/passport/process", response_class=HTMLResponse)
    async def process_passport(
        request: Request,
        factory: GrpcClientFactory = Depends(get_factory),
        passport_number: str = Form(default=""),
    ):
        """Trigger passport processing via the Passport Engine."""

        generated_number = passport_number.strip() or f"P{uuid.uuid4().hex[:8].upper()}"
        grpc_status = "UNKNOWN"
        message: str
        error: str | None = None

        if settings.enable_mock_data:
            grpc_status = "SUCCESS"
            message = f"[mock] Passport {generated_number} processed"
        else:
            try:
                with factory.passport_engine() as stub:
                    grpc_response = stub.ProcessPassport(
                        passport_engine_pb2.PassportRequest(passport_number=generated_number)
                    )
                    grpc_status = grpc_response.status
                    message = f"Passport {generated_number} processed with status {grpc_status}"
            except grpc.RpcError as exc:  # pragma: no cover - requires gRPC server
                error = exc.details() if hasattr(exc, "details") else str(exc)
                LOGGER.warning("Passport processing failed: %s", error)
                message = f"Failed to process passport {generated_number}"
            except Exception as exc:  # pragma: no cover - defensive guard
                error = str(exc)
                LOGGER.exception("Unexpected passport processing failure")
                message = f"Failed to process passport {generated_number}"

        operation_log.add(
            OperationRecord(
                timestamp=datetime.utcnow(),
                category="passport",
                identifier=generated_number,
                status=grpc_status if error is None else "ERROR",
                message=message if error is None else f"{message}: {error}",
            )
        )

        result_payload = {
            "passport_number": generated_number,
            "status": grpc_status,
            "success": error is None and grpc_status.upper() == "SUCCESS",
            "error": error,
            "message": message if error is None else error,
        }

        # Store in cache for E2E testing
        _result_cache["process_result"] = result_payload

        return templates.TemplateResponse(
            "passport.html",
            {
                "request": request,
                "settings": settings,
                "process_result": result_payload,
                "inspection_result": _result_cache["inspection_result"],
            },
        )

    @app.post("/passport/inspect", response_class=HTMLResponse)
    async def inspect_passport(
        request: Request,
        factory: GrpcClientFactory = Depends(get_factory),
        passport_number: str = Form(...),
    ):
        """Verify a passport using the Inspection System."""

        passport_number = passport_number.strip().upper()
        inspection_text: str = ""
        status = "ERROR"
        error: str | None = None

        if not passport_number:
            error = "Passport number is required"
        elif settings.enable_mock_data:
            # Simulate error for fake/invalid passport numbers
            if passport_number.upper().startswith("FAKE") or len(passport_number) < 6:
                status = "ERROR"
                inspection_text = f"ERROR: Passport {passport_number} NOT FOUND\nStatus: INVALID\nConnection: REFUSED"
            else:
                status = "SUCCESS"
                inspection_text = (
                    f"VALID: Passport {passport_number} (mock data)\n"
                    "Issue Date: 2024-01-01\n"
                    "Expiry Date: 2034-01-01\n"
                    "Data Groups: 4"
                )
        else:
            try:
                with factory.inspection_system() as stub:
                    grpc_response = stub.Inspect(
                        inspection_system_pb2.InspectRequest(item=passport_number)
                    )
                    inspection_text = grpc_response.result
                    status = "SUCCESS" if "VALID" in inspection_text.upper() else "WARNING"
            except grpc.RpcError as exc:  # pragma: no cover - requires gRPC server
                error = exc.details() if hasattr(exc, "details") else str(exc)
                LOGGER.warning("Passport inspection failed: %s", error)
            except Exception as exc:  # pragma: no cover
                error = str(exc)
                LOGGER.exception("Unexpected passport inspection failure")

        operation_log.add(
            OperationRecord(
                timestamp=datetime.utcnow(),
                category="inspection",
                identifier=passport_number or "unknown",
                status=status if error is None else "ERROR",
                message=inspection_text or (error or ""),
            )
        )

        inspection_payload = {
            "passport_number": passport_number,
            "status": status,
            "result": inspection_text,
            "error": error,
        }

        # Store in cache for E2E testing
        _result_cache["inspection_result"] = inspection_payload

        return templates.TemplateResponse(
            "passport.html",
            {
                "request": request,
                "settings": settings,
                "process_result": _result_cache["process_result"],
                "inspection_result": inspection_payload,
            },
        )

    @app.get("/mdl", response_class=HTMLResponse)
    async def mdl_console(request: Request):
        """Render Mobile Driving Licence workflows."""

        return templates.TemplateResponse(
            "mdl.html",
            {
                "request": request,
                "settings": settings,
                "create_result": None,
                "lookup_result": None,
            },
        )

    @app.post("/mdl/create", response_class=HTMLResponse)
    async def create_mdl(
        request: Request,
        factory: GrpcClientFactory = Depends(get_factory),
        license_number: str = Form(...),
        first_name: str = Form(...),
        last_name: str = Form(...),
        user_id: str = Form(default="test_user"),
        date_of_birth: str = Form(default="1990-01-01"),
        issuing_authority: str = Form(default="Test DMV"),
        issue_date: str = Form(default="2024-01-01"),
        expiry_date: str = Form(default="2034-01-01"),
    ):
        """Create an MDL via the MDL Engine."""

        license_number = license_number.strip().upper()
        status = "ERROR"
        error: str | None = None
        mdl_id = None

        if mdl_engine_pb2 is None:
            error = "MDL engine proto not available in this build"
        elif settings.enable_mock_data:
            mdl_id = f"mdl_{license_number.lower()}"
            status = "PENDING_SIGNATURE"
        else:
            try:
                with factory.mdl_engine() as stub:
                    if stub is None:
                        msg = "MDL engine stub unavailable"
                        raise RuntimeError(msg)
                    grpc_response = stub.CreateMDL(
                        mdl_engine_pb2.CreateMDLRequest(
                            user_id=user_id.strip(),
                            license_number=license_number,
                            first_name=first_name.strip(),
                            last_name=last_name.strip(),
                            date_of_birth=date_of_birth.strip(),
                            issuing_authority=issuing_authority.strip(),
                            issue_date=issue_date.strip(),
                            expiry_date=expiry_date.strip(),
                        )
                    )
                    mdl_id = grpc_response.mdl_id
                    status = grpc_response.status or "UNKNOWN"
            except grpc.RpcError as exc:  # pragma: no cover - requires gRPC server
                error = exc.details() if hasattr(exc, "details") else str(exc)
                LOGGER.warning("CreateMDL failed: %s", error)
            except Exception as exc:  # pragma: no cover
                error = str(exc)
                LOGGER.exception("Unexpected MDL creation failure")

        operation_log.add(
            OperationRecord(
                timestamp=datetime.utcnow(),
                category="mdl",
                identifier=license_number,
                status=status if error is None else "ERROR",
                message=mdl_id or (error or ""),
            )
        )

        create_payload = {
            "license_number": license_number,
            "mdl_id": mdl_id,
            "status": status,
            "error": error,
            "success": error is None and mdl_id is not None,
            "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "first_name": first_name,
            "last_name": last_name,
            "user_id": user_id,
        }

        return templates.TemplateResponse(
            "mdl.html",
            {
                "request": request,
                "settings": settings,
                "create_result": create_payload,
                "lookup_result": None,
            },
        )

    @app.post("/mdl/lookup", response_class=HTMLResponse)
    async def lookup_mdl(
        request: Request,
        factory: GrpcClientFactory = Depends(get_factory),
        license_number: str = Form(...),
    ):
        """Fetch MDL details by license number."""

        license_number = license_number.strip().upper()
        mdl_payload: dict[str, Any] = {}
        error: str | None = None

        if mdl_engine_pb2 is None:
            error = "MDL engine proto not available in this build"
        elif settings.enable_mock_data:
            mdl_payload = {
                "mdl_id": f"mdl_{license_number.lower()}",
                "license_number": license_number,
                "first_name": "John",  # Use consistent test name
                "middle_name": "A",
                "last_name": "User",
                "status": "PENDING_SIGNATURE",
                "issue_date": "2024-01-01",
                "expiry_date": "2029-01-01",
                "document_number": f"DOC{license_number}",
                "issuing_authority": "Department of Motor Vehicles",
                "date_of_birth": "1985-05-15",
                "gender": "M",
                "height": "175",
                "weight": "70",
                "eye_color": "Brown",
            }
        else:
            try:
                with factory.mdl_engine() as stub:
                    if stub is None:
                        msg = "MDL engine stub unavailable"
                        raise RuntimeError(msg)
                    grpc_response = stub.GetMDL(
                        mdl_engine_pb2.GetMDLRequest(license_number=license_number)
                    )
                    mdl_payload = _serialize_mdl_response(grpc_response)
            except grpc.RpcError as exc:  # pragma: no cover - requires gRPC server
                error = exc.details() if hasattr(exc, "details") else str(exc)
                LOGGER.warning("GetMDL failed: %s", error)
            except AttributeError as exc:
                # Older server builds might return a different payload structure
                error = f"MDL response not understood: {exc}"  # pragma: no cover
                LOGGER.warning("GetMDL returned unexpected structure: %s", exc)
            except Exception as exc:  # pragma: no cover
                error = str(exc)
                LOGGER.exception("Unexpected MDL lookup failure")

        lookup_result = {
            "license_number": license_number,
            "mdl": mdl_payload,
            "error": error,
        }

        return templates.TemplateResponse(
            "mdl.html",
            {
                "request": request,
                "settings": settings,
                "create_result": None,
                "lookup_result": lookup_result,
            },
        )

    # CSCA Service Routes
    @app.get("/csca", response_class=HTMLResponse)
    async def csca_console(request: Request):
        """Render CSCA Service management interface."""
        return templates.TemplateResponse(
            "csca.html",
            {
                "request": request,
                "settings": settings,
                "certificates": None,
                "create_result": None,
                "operation_result": None,
            },
        )

    @app.post("/csca/create", response_class=HTMLResponse)
    async def create_csca_certificate(
        request: Request,
        country: str = Form(default="US"),
        organization: str = Form(default="Test Org"),
    ):
        """Create a new CSCA certificate."""
        # Mock implementation for demonstration
        cert_id = f"CSCA_{uuid.uuid4().hex[:8].upper()}"
        create_result = {
            "status": "SUCCESS",
            "certificate_id": cert_id,
            "message": f"Certificate Created Successfully\nID: {cert_id}\nStatus: SUCCESS\nOrganization: {organization}\nCountry: {country}",
            "valid_from": datetime.utcnow().strftime("%Y-%m-%d"),
            "valid_to": "2034-01-01",
            "country": country,
            "organization": organization,
        }

        return templates.TemplateResponse(
            "csca.html",
            {
                "request": request,
                "settings": settings,
                "certificates": None,
                "create_result": create_result,
                "operation_result": None,
            },
        )

    # Document Signer Routes
    @app.get("/document-signer", response_class=HTMLResponse)
    async def document_signer_console(request: Request):
        """Render Document Signer interface."""
        return templates.TemplateResponse(
            "document_signer.html",
            {
                "request": request,
                "settings": settings,
                "signing_result": None,
                "verification_result": None,
                "dsc_certificates": None,
            },
        )

    @app.post("/document-signer/sign", response_class=HTMLResponse)
    async def sign_document(request: Request):
        """Sign a document."""
        # Mock implementation
        signing_result = {
            "status": "SUCCESS",
            "document_id": f"DOC_{uuid.uuid4().hex[:8].upper()}",
            "signature_id": f"SIG_{uuid.uuid4().hex[:8].upper()}",
            "signed_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "algorithm": "RSA-SHA256",
        }

        return templates.TemplateResponse(
            "document_signer.html",
            {
                "request": request,
                "settings": settings,
                "signing_result": signing_result,
                "verification_result": None,
                "dsc_certificates": None,
            },
        )

    # mDoc Engine Routes
    @app.get("/mdoc", response_class=HTMLResponse)
    async def mdoc_console(request: Request):
        """Render mDoc Engine interface."""
        return templates.TemplateResponse(
            "mdoc.html",
            {
                "request": request,
                "settings": settings,
                "creation_result": None,
                "verification_result": None,
                "document_types": ["identity_card", "passport", "driving_license", "visa"],
            },
        )

    @app.post("/mdoc/create", response_class=HTMLResponse)
    async def create_mdoc(request: Request):
        """Create a new mDoc."""
        # Mock implementation
        creation_result = {
            "status": "SUCCESS",
            "document_id": f"MDOC_{uuid.uuid4().hex[:8].upper()}",
            "document_type": "identity_card",
            "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "qr_code_data": f"mdoc://verify/{uuid.uuid4().hex}",
        }

        return templates.TemplateResponse(
            "mdoc.html",
            {
                "request": request,
                "settings": settings,
                "creation_result": creation_result,
                "verification_result": None,
                "document_types": ["identity_card", "passport", "driving_license", "visa"],
            },
        )

    # DTC Engine Routes
    @app.get("/dtc", response_class=HTMLResponse)
    async def dtc_console(request: Request):
        """Render DTC Engine interface."""
        return templates.TemplateResponse(
            "dtc.html",
            {
                "request": request,
                "settings": settings,
                "creation_result": None,
                "verification_result": None,
                "dtc_types": ["emergency", "visitor", "temporary"],
            },
        )

    @app.post("/dtc/create", response_class=HTMLResponse)
    async def create_dtc(request: Request):
        """Create a new Digital Travel Credential."""
        # Mock implementation
        creation_result = {
            "status": "SUCCESS",
            "credential_id": f"DTC_{uuid.uuid4().hex[:8].upper()}",
            "dtc_type": "emergency",
            "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "qr_code_data": f"dtc://verify/{uuid.uuid4().hex}",
            "access_code": f"{uuid.uuid4().hex[:6].upper()}",
        }

        return templates.TemplateResponse(
            "dtc.html",
            {
                "request": request,
                "settings": settings,
                "creation_result": creation_result,
                "verification_result": None,
                "dtc_types": ["emergency", "visitor", "temporary"],
            },
        )

    # PKD Service Routes
    @app.get("/pkd", response_class=HTMLResponse)
    async def pkd_console(request: Request):
        """Render PKD Service interface."""
        # Extract query parameters for search functionality
        search_query = request.query_params.get("search", "")
        country_filter = request.query_params.get("country", "")
        status_filter = request.query_params.get("status", "")

        return templates.TemplateResponse(
            "pkd.html",
            {
                "request": request,
                "settings": settings,
                "sync_result": None,
                "certificates": None,
                "master_lists": None,
                "search_query": search_query,
                "country_filter": country_filter,
                "status_filter": status_filter,
                "sync_status": {
                    "sources": [
                        {
                            "id": "icao_pkd",
                            "name": "ICAO PKD",
                            "status": "HEALTHY",
                            "last_sync": "2024-01-15 10:30:00",
                            "certificate_count": 850,
                        },
                        {
                            "id": "national_pkd",
                            "name": "National PKD",
                            "status": "HEALTHY",
                            "last_sync": "2024-01-15 09:15:00",
                            "certificate_count": 397,
                        },
                    ]
                },
                "statistics": {
                    "total_certificates": 1247,
                    "active_certificates": 1150,
                    "expired_certificates": 85,
                    "revoked_certificates": 12,
                    "active_lists": 23,
                    "last_sync": "2024-01-15 10:30:00",
                    "sync_status": "SUCCESS",
                    "top_countries": [
                        {"code": "US", "count": 324},
                        {"code": "DE", "count": 187},
                        {"code": "FR", "count": 156},
                        {"code": "GB", "count": 143},
                        {"code": "JP", "count": 89},
                    ],
                    "expiring_30_days": 23,
                    "expiring_7_days": 5,
                    "expired_today": 2,
                    "storage_used": "2.4 GB",
                    "last_backup": "2024-01-14 23:00:00",
                    "sync_errors_24h": 0,
                },
            },
        )

    @app.post("/pkd/sync", response_class=HTMLResponse)
    async def sync_pkd(request: Request):
        """Synchronize PKD data."""
        # Mock implementation with comprehensive sync result
        sync_result = {
            "status": "SUCCESS",
            "synchronized_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "certificates_added": 12,
            "certificates_updated": 5,
            "lists_processed": 3,
            "sources_synced": 4,
            "duration": "2.5 minutes",
        }

        return templates.TemplateResponse(
            "pkd.html",
            {
                "request": request,
                "settings": settings,
                "sync_result": sync_result,
                "certificates": None,
                "master_lists": None,
                "sync_status": {
                    "sources": [
                        {
                            "id": "icao_pkd",
                            "name": "ICAO PKD",
                            "status": "SYNCED",
                            "last_sync": sync_result["synchronized_at"],
                            "certificate_count": 862,
                        }
                    ]
                },
                "statistics": {
                    "total_certificates": 1259,
                    "active_lists": 23,
                    "last_sync": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    "sync_status": "SUCCESS",
                },
            },
        )

    # Trust Anchor Routes
    @app.get("/trust-anchor", response_class=HTMLResponse)
    async def trust_anchor_console(request: Request):
        """Render Trust Anchor interface."""
        # Extract query parameters for search functionality
        search_query = request.query_params.get("search", "")
        trust_level = request.query_params.get("trust_level", "")

        return templates.TemplateResponse(
            "trust_anchor.html",
            {
                "request": request,
                "settings": settings,
                "validation_result": None,
                "trusted_certificates": None,
                "expiring_certificates": None,
                "search_query": search_query,
                "trust_level": trust_level,
                "service_status": {
                    "trust_anchor": {
                        "status": "HEALTHY",
                        "uptime": "72h 15m",
                        "memory_usage": "45%",
                        "response_time": "12ms",
                    },
                    "certificate_store": {
                        "status": "HEALTHY",
                        "certificate_count": 156,
                        "storage_used": "2.3GB",
                        "last_sync": "2024-01-15 10:30:00",
                    },
                    "openxpki": {
                        "status": "HEALTHY",
                        "connection_status": "Connected",
                        "version": "3.20.1",
                        "last_check": "2024-01-15 10:29:45",
                    },
                },
            },
        )

    @app.post("/trust-anchor/validate", response_class=HTMLResponse)
    async def validate_certificate(request: Request):
        """Validate a certificate."""
        # Mock implementation
        validation_result = {
            "is_valid": True,
            "trust_level": "HIGH",
            "certificate_info": {
                "subject": "CN=Test CSCA, O=Test Organization, C=US",
                "issuer": "CN=Root CA, O=Test Root, C=US",
                "serial_number": "1234567890ABCDEF",
                "valid_from": "2024-01-01",
                "valid_to": "2034-01-01",
            },
            "chain_valid": True,
            "signature_valid": True,
            "time_valid": True,
            "revocation_status": "Not Revoked",
        }

        return templates.TemplateResponse(
            "trust_anchor.html",
            {
                "request": request,
                "settings": settings,
                "validation_result": validation_result,
                "trusted_certificates": None,
                "expiring_certificates": None,
                "service_status": {
                    "trust_anchor": {
                        "status": "HEALTHY",
                        "uptime": "72h 15m",
                        "memory_usage": "45%",
                        "response_time": "12ms",
                    },
                    "certificate_store": {
                        "status": "HEALTHY",
                        "certificate_count": 156,
                        "storage_used": "2.3GB",
                        "last_sync": "2024-01-15 10:30:00",
                    },
                    "openxpki": {
                        "status": "HEALTHY",
                        "connection_status": "Connected",
                        "version": "3.20.1",
                        "last_check": "2024-01-15 10:29:45",
                    },
                },
            },
        )

    # Admin Routes
    @app.get("/admin", response_class=HTMLResponse)
    async def admin_console(request: Request):
        """Render Administration interface."""
        return templates.TemplateResponse(
            "admin.html",
            {
                "request": request,
                "settings": settings,
                "system_stats": {
                    "active_services": 9,
                    "total_certificates": 1247,
                    "documents_processed": 5643,
                    "system_uptime": "72h 15m",
                },
                "health_status": {
                    "csca_service": {"status": "HEALTHY", "response_time": "15"},
                    "document_signer": {"status": "HEALTHY", "response_time": "18"},
                    "passport_engine": {"status": "HEALTHY", "response_time": "22"},
                    "inspection_system": {"status": "HEALTHY", "response_time": "25"},
                    "mdl_engine": {"status": "HEALTHY", "response_time": "19"},
                    "mdoc_engine": {"status": "HEALTHY", "response_time": "21"},
                    "dtc_engine": {"status": "HEALTHY", "response_time": "17"},
                    "pkd_service": {"status": "HEALTHY", "response_time": "28"},
                    "trust_anchor": {"status": "HEALTHY", "response_time": "12"},
                },
                "services": {
                    "csca": {
                        "status": "RUNNING",
                        "port": "50051",
                        "memory_usage": "45MB",
                        "cpu_usage": "2.1%",
                        "uptime": "72h 15m",
                    },
                    "document_signer": {
                        "status": "RUNNING",
                        "port": "50052",
                        "memory_usage": "38MB",
                        "cpu_usage": "1.8%",
                        "uptime": "72h 15m",
                    },
                    "passport_engine": {
                        "status": "RUNNING",
                        "port": "50053",
                        "memory_usage": "52MB",
                        "cpu_usage": "3.2%",
                        "uptime": "72h 15m",
                    },
                    "inspection_system": {
                        "status": "RUNNING",
                        "port": "50054",
                        "memory_usage": "41MB",
                        "cpu_usage": "2.5%",
                        "uptime": "72h 15m",
                    },
                    "mdl_engine": {
                        "status": "RUNNING",
                        "port": "50055",
                        "memory_usage": "47MB",
                        "cpu_usage": "2.8%",
                        "uptime": "72h 15m",
                    },
                    "mdoc_engine": {
                        "status": "RUNNING",
                        "port": "50056",
                        "memory_usage": "44MB",
                        "cpu_usage": "2.3%",
                        "uptime": "72h 15m",
                    },
                    "dtc_engine": {
                        "status": "RUNNING",
                        "port": "50057",
                        "memory_usage": "39MB",
                        "cpu_usage": "1.9%",
                        "uptime": "72h 15m",
                    },
                    "pkd_service": {
                        "status": "RUNNING",
                        "port": "50058",
                        "memory_usage": "61MB",
                        "cpu_usage": "3.8%",
                        "uptime": "72h 15m",
                    },
                    "trust_anchor": {
                        "status": "RUNNING",
                        "port": "50059",
                        "memory_usage": "35MB",
                        "cpu_usage": "1.5%",
                        "uptime": "72h 15m",
                    },
                },
                "config": {
                    "environment": settings.environment,
                    "debug_mode": settings.environment == "development",
                    "host": "0.0.0.0",
                    "port": 8000,
                    "max_workers": 4,
                    "tls_enabled": False,
                    "cert_validation": "strict",
                    "api_key_required": True,
                    "session_timeout": 30,
                    "log_level": "INFO",
                    "log_rotation": "daily",
                    "log_directory": "/var/log/marty",
                    "max_log_files": 30,
                    "openxpki_url": "https://openxpki.example.com",
                    "pkd_sync_enabled": True,
                    "pkd_sync_interval": 24,
                    "notification_email": "admin@example.com",
                },
                "metrics": {
                    "cpu_usage": 15,
                    "memory_usage": 42,
                    "disk_usage": 28,
                    "network_io": 1.2,
                    "network_in": 0.8,
                    "network_out": 0.4,
                },
                "log_entries": [
                    {
                        "timestamp": "2024-01-15 10:35:22",
                        "service": "csca",
                        "level": "INFO",
                        "message": "Certificate created successfully",
                    },
                    {
                        "timestamp": "2024-01-15 10:34:15",
                        "service": "passport_engine",
                        "level": "INFO",
                        "message": "Passport processed: P12345678",
                    },
                    {
                        "timestamp": "2024-01-15 10:33:45",
                        "service": "inspection_system",
                        "level": "WARNING",
                        "message": "Invalid passport format detected",
                    },
                    {
                        "timestamp": "2024-01-15 10:32:30",
                        "service": "pkd_service",
                        "level": "INFO",
                        "message": "Master list synchronized",
                    },
                ],
                "db_stats": {
                    "size": "4.7GB",
                    "certificate_count": 1247,
                    "document_count": 5643,
                    "log_count": 156789,
                },
            },
        )

    return app


def _serialize_mdl_response(response: Any) -> dict[str, Any]:
    """Convert a gRPC MDL response into plain dict for the template."""

    payload: dict[str, Any] = {}

    for field in (
        "mdl_id",
        "license_number",
        "first_name",
        "last_name",
        "date_of_birth",
        "issuing_authority",
        "issue_date",
        "expiry_date",
        "status",
        "error_message",
    ):
        value = getattr(response, field, None)
        if value:
            payload[field] = value

    if getattr(response, "signature_info", None):
        sig_info = response.signature_info
        payload["signature_info"] = {
            "signature_date": getattr(sig_info, "signature_date", ""),
            "signer_id": getattr(sig_info, "signer_id", ""),
            "is_valid": getattr(sig_info, "is_valid", False),
        }

    categories = []
    for category in getattr(response, "license_categories", []):
        categories.append(
            {
                "category_code": getattr(category, "category_code", ""),
                "issue_date": getattr(category, "issue_date", ""),
                "expiry_date": getattr(category, "expiry_date", ""),
                "restrictions": list(getattr(category, "restrictions", [])),
            }
        )
    if categories:
        payload["license_categories"] = categories

    additional_fields = []
    for addition in getattr(response, "additional_fields", []):
        additional_fields.append(
            {
                "field_name": getattr(addition, "field_name", ""),
                "field_value": getattr(addition, "field_value", ""),
            }
        )
    if additional_fields:
        payload["additional_fields"] = additional_fields

    if getattr(response, "portrait", None):
        payload["portrait_present"] = True

    return payload


app = create_app()

__all__ = ["app", "create_app"]
