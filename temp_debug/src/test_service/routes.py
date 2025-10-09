"""
API routes for test-service service using DRY patterns.
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from src.test_service.app.core.config import create_test_service_config
from src.test_service.app.services.test_service_service import TestServiceService

router = APIRouter(tags=["test-service"])


# Dependency to get service configuration
def get_config():
    """Get service configuration."""
    return create_test_service_config()


# Dependency to get service instance
def get_test_service_service(config=Depends(get_config)):
    """Get test-service service instance."""
    return TestServiceService(config)


# Request/Response models
class StatusResponse(BaseModel):
    """Service status response."""

    service_name: str
    version: str
    is_healthy: bool
    timestamp: str


# Add your custom models here
# Example:
# class ProcessRequest(BaseModel):
#     """Document processing request."""
#     document_id: str
#     document_data: bytes
#     options: Dict[str, Any] = {}
#
# class ProcessResponse(BaseModel):
#     """Document processing response."""
#     success: bool
#     result: str | None = None
#     error: str | None = None
#     metadata: Dict[str, Any] = {}


@router.get("/health", response_model=StatusResponse)
async def get_health_status(
    service: TestServiceService = Depends(get_test_service_service),
) -> StatusResponse:
    """
    Get service health status.

    Returns:
        Service health and status information
    """
    try:
        status = await service.get_status()
        return StatusResponse(**status)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


@router.get("/status", response_model=StatusResponse)
async def get_service_status(
    service: TestServiceService = Depends(get_test_service_service),
) -> StatusResponse:
    """
    Get detailed service status.

    Returns:
        Detailed service status information
    """
    try:
        status = await service.get_detailed_status()
        return StatusResponse(**status)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")


# Add your API endpoints here
# Example:
# @router.post("/process", response_model=ProcessResponse)
# async def process_document(
#     request: ProcessRequest,
#     service: TestServiceService = Depends(get_test_service_service)
# ) -> ProcessResponse:
#     """
#     Process a document.
#
#     Args:
#         request: Processing request with document data
#         service: Service instance
#
#     Returns:
#         Processing result
#     """
#     try:
#         result = await service.process_document(
#             document_id=request.document_id,
#             document_data=request.document_data,
#             options=request.options
#         )
#         return ProcessResponse(**result)
#     except ValueError as e:
#         raise HTTPException(status_code=400, detail=str(e))
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")
#
# @router.get("/documents/{document_id}/status")
# async def get_document_status(
#     document_id: str,
#     service: TestServiceService = Depends(get_test_service_service)
# ) -> Dict[str, Any]:
#     """Get processing status for a document."""
#     try:
#         status = await service.get_document_status(document_id)
#         if not status:
#             raise HTTPException(status_code=404, detail="Document not found")
#         return status
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")
