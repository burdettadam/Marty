"""
TD-2 gRPC server implementation.

This module provides the gRPC s        except Exception as e:
            logger.exception("Unexpected error in CreateTD2Document")
            context.set_code(grpc.StatusCode.INTERNAL)er for TD-2 document op        except Exception as e:
            logger.exception("Unexpected error in IssueTD2Document")
            context.set_code(grpc.StatusCode.INTERNAL)tions,
implementing the TD2Service interface defined in the protobuf specification.
"""

import logging
from datetime import date, datetime

import grpc
from grpc import StatusCode

# Import generated protobuf classes (these would be generated from proto files)
# For now, we'll create mock implementations
from src.services.td2_service import (
    TD2IssueError,
    TD2Service,
    TD2ServiceError,
    TD2VerificationError,
)
from src.shared.models.td2 import (
    PersonalData,
    PolicyConstraints,
    TD2DocumentCreateRequest,
    TD2DocumentData,
    TD2DocumentSearchRequest,
    TD2DocumentType,
    TD2DocumentVerifyRequest,
    TD2Status,
)

logger = logging.getLogger(__name__)


class TD2ServiceGRPC:
    """gRPC implementation of TD2Service."""

    def __init__(self, td2_service: TD2Service) -> None:
        """
        Initialize gRPC service.

        Args:
            td2_service: Underlying TD-2 service
        """
        self.td2_service = td2_service
        logger.info("TD-2 gRPC service initialized")

    async def CreateTD2Document(self, request, context):
        """Create a new TD-2 document."""
        try:
            logger.info("gRPC CreateTD2Document called")

            # Convert gRPC request to internal model
            create_request = self._convert_create_request(request)

            # Create document
            document = await self.td2_service.create_document(
                create_request,
                created_by=context.auth_context().get("user_id")
            )

            # Convert to gRPC response
            response = self._convert_create_response(document, True, "Document created successfully")

            logger.info(f"TD-2 document created via gRPC: {document.document_id}")
        except TD2IssueError as e:
            logger.exception(f"TD-2 creation error: {e}")
            return self._convert_create_response(None, False, str(e), [str(e)])
        except Exception as e:
            logger.exception(f"Unexpected error in CreateTD2Document: {e}")
            context.set_code(StatusCode.INTERNAL)
            context.set_details(f"Internal error: {e!s}")
            raise
        else:
            return response

    async def IssueTD2Document(self, request, context):
        """Issue (finalize) a TD-2 document."""
        try:
            logger.info(f"gRPC IssueTD2Document called: {request.document_id}")

            # Issue document
            document = await self.td2_service.issue_document(
                request.document_id,
                generate_chip_data=request.generate_chip_data
            )

            # Convert to gRPC response
            response = self._convert_issue_response(document, True, "Document issued successfully")

            logger.info(f"TD-2 document issued via gRPC: {document.document_id}")
        except TD2ServiceError as e:
            logger.exception(f"TD-2 issuance error: {e}")
            return self._convert_issue_response(None, False, str(e), [str(e)])
        except Exception as e:
            logger.exception(f"Unexpected error in IssueTD2Document: {e}")
            context.set_code(StatusCode.INTERNAL)
            context.set_details(f"Internal error: {e!s}")
            raise
        else:
            return response

    async def VerifyTD2Document(self, request, context):
        """Verify a TD-2 document."""
        try:
            logger.info("gRPC VerifyTD2Document called")

            # Convert gRPC request to internal model
            verify_request = self._convert_verify_request(request)

            # Verify document
            result = await self.td2_service.verify_document(verify_request)

            # Get document for response (if available)
            document = None
            if hasattr(request, "document_id") and request.document_id:
                try:
                    document = await self.td2_service.get_document(request.document_id)
                except TD2ServiceError:
                    pass  # Document not found, continue with verification result only

            # Convert to gRPC response
            response = self._convert_verify_response(result, document, True, "Verification completed")

            logger.info(f"TD-2 verification completed via gRPC: valid={result.is_valid}")
        except TD2VerificationError as e:
            logger.exception(f"TD-2 verification error: {e}")
            return self._convert_verify_response(None, None, False, str(e))
        except Exception as e:
            logger.exception(f"Unexpected error in VerifyTD2Document: {e}")
            context.set_code(StatusCode.INTERNAL)
            context.set_details(f"Internal error: {e!s}")
            raise
        else:
            return response

    async def GetTD2Document(self, request, context):
        """Get a TD-2 document by ID."""
        try:
            logger.info(f"gRPC GetTD2Document called: {request.document_id}")

            # Get document
            document = await self.td2_service.get_document(request.document_id)

            # Convert to gRPC response
            response = self._convert_get_response(document, True, "Document retrieved successfully")

            logger.info(f"TD-2 document retrieved via gRPC: {document.document_id}")
        except TD2ServiceError as e:
            logger.exception(f"TD-2 get error: {e}")
            return self._convert_get_response(None, False, str(e))
        except Exception as e:
            logger.exception(f"Unexpected error in GetTD2Document: {e}")
            context.set_code(StatusCode.INTERNAL)
            context.set_details(f"Internal error: {e!s}")
            raise
        else:
            return response

    async def SearchTD2Documents(self, request, context):
        """Search TD-2 documents."""
        try:
            logger.info(f"gRPC SearchTD2Documents called: query={getattr(request, 'query', '')}")

            # Convert gRPC request to internal model
            search_request = self._convert_search_request(request)

            # Search documents
            search_response = await self.td2_service.search_documents(search_request)

            # Convert to gRPC response
            response = self._convert_search_response(search_response)

            logger.info(f"TD-2 search completed via gRPC: {len(search_response.documents)} results")
        except TD2ServiceError as e:
            logger.exception(f"TD-2 search error: {e}")
            return self._convert_search_response_error(str(e))
        except Exception as e:
            logger.exception(f"Unexpected error in SearchTD2Documents: {e}")
            context.set_code(StatusCode.INTERNAL)
            context.set_details(f"Internal error: {e!s}")
            raise
        else:
            return response

    async def UpdateTD2DocumentStatus(self, request, context):
        """Update TD-2 document status."""
        try:
            logger.info(f"gRPC UpdateTD2DocumentStatus called: {request.document_id} -> {request.new_status}")

            # Convert status enum
            new_status = self._convert_status_from_grpc(request.new_status)

            # Update status
            document = await self.td2_service.update_status(
                request.document_id,
                new_status,
                getattr(request, "reason", None)
            )

            # Convert to gRPC response
            response = self._convert_update_status_response(document, True, "Status updated successfully")

            logger.info(f"TD-2 document status updated via gRPC: {document.document_id}")
        except TD2ServiceError as e:
            logger.exception(f"TD-2 status update error: {e}")
            return self._convert_update_status_response(None, False, str(e))
        except Exception as e:
            logger.exception(f"Unexpected error in UpdateTD2DocumentStatus: {e}")
            context.set_code(StatusCode.INTERNAL)
            context.set_details(f"Internal error: {e!s}")
            raise
        else:
            return response

    async def RevokeTD2Document(self, request, context):
        """Revoke a TD-2 document."""
        try:
            logger.info(f"gRPC RevokeTD2Document called: {request.document_id}")

            # Revoke document
            document = await self.td2_service.revoke_document(
                request.document_id,
                getattr(request, "reason", "No reason provided")
            )

            # Convert to gRPC response
            response = self._convert_revoke_response(document, True, "Document revoked successfully")

            logger.info(f"TD-2 document revoked via gRPC: {document.document_id}")
        except TD2ServiceError as e:
            logger.exception(f"TD-2 revocation error: {e}")
            return self._convert_revoke_response(None, False, str(e))
        except Exception as e:
            logger.exception(f"Unexpected error in RevokeTD2Document: {e}")
            context.set_code(StatusCode.INTERNAL)
            context.set_details(f"Internal error: {e!s}")
            raise
        else:
            return response

    async def RenewTD2Document(self, request, context):
        """Renew a TD-2 document."""
        try:
            logger.info(f"gRPC RenewTD2Document called: {request.document_id}")

            # Parse new expiry date
            new_expiry_date = datetime.fromisoformat(request.new_expiry_date).date()

            # Convert policy constraints if provided
            updated_constraints = None
            if hasattr(request, "updated_constraints") and request.updated_constraints:
                updated_constraints = self._convert_policy_constraints_from_grpc(request.updated_constraints)

            # Renew document
            document = await self.td2_service.renew_document(
                request.document_id,
                new_expiry_date,
                updated_constraints
            )

            # Convert to gRPC response
            response = self._convert_renew_response(document, True, "Document renewed successfully")

            logger.info(f"TD-2 document renewed via gRPC: {document.document_id}")
        except TD2ServiceError as e:
            logger.exception(f"TD-2 renewal error: {e}")
            return self._convert_renew_response(None, False, str(e))
        except ValueError as e:
            logger.exception(f"TD-2 renewal date error: {e}")
            return self._convert_renew_response(None, False, f"Invalid date format: {e!s}")
        except Exception as e:
            logger.exception(f"Unexpected error in RenewTD2Document: {e}")
            context.set_code(StatusCode.INTERNAL)
            context.set_details(f"Internal error: {e!s}")
            raise
        else:
            return response

    async def GetTD2Statistics(self, request, context):
        """Get TD-2 document statistics."""
        try:
            logger.info("gRPC GetTD2Statistics called")

            # Get statistics
            stats = await self.td2_service.get_statistics()

            # Convert to gRPC response
            response = self._convert_statistics_response(stats)

            logger.info("TD-2 statistics retrieved via gRPC")
        except Exception as e:
            logger.exception(f"Unexpected error in GetTD2Statistics: {e}")
            context.set_code(StatusCode.INTERNAL)
            context.set_details(f"Internal error: {e!s}")
            raise
        else:
            return response

    async def GetExpiringTD2Documents(self, request, context):
        """Get expiring TD-2 documents."""
        try:
            days_until_expiry = getattr(request, "days_until_expiry", 30)
            logger.info(f"gRPC GetExpiringTD2Documents called: {days_until_expiry} days")

            # Get expiring documents
            documents = await self.td2_service.get_expiring_documents(days_until_expiry)

            # Apply filters if provided
            if hasattr(request, "document_type") and request.document_type:
                doc_type = self._convert_document_type_from_grpc(request.document_type)
                documents = [d for d in documents if d.document_data.document_type == doc_type]

            if hasattr(request, "issuing_state") and request.issuing_state:
                documents = [d for d in documents if d.document_data.issuing_state == request.issuing_state]

            # Apply pagination
            limit = getattr(request, "limit", 100)
            offset = getattr(request, "offset", 0)
            paginated_documents = documents[offset:offset + limit]

            # Convert to gRPC response
            response = self._convert_expiring_response(paginated_documents, len(documents))

            logger.info(f"TD-2 expiring documents retrieved via gRPC: {len(paginated_documents)} results")
        except Exception as e:
            logger.exception(f"Unexpected error in GetExpiringTD2Documents: {e}")
            context.set_code(StatusCode.INTERNAL)
            context.set_details(f"Internal error: {e!s}")
            raise
        else:
            return response

    # Conversion helper methods (mock implementations for protobuf conversion)

    def _convert_create_request(self, grpc_request) -> TD2DocumentCreateRequest:
        """Convert gRPC create request to internal model."""
        # This would convert from protobuf to internal models
        # For now, return a mock request
        return TD2DocumentCreateRequest(
            personal_data=PersonalData(
                primary_identifier="TEST",
                nationality="USA",
                date_of_birth=date.today(),
                gender="M"
            ),
            document_data=TD2DocumentData(
                document_type=TD2DocumentType.ID,
                document_number="TEST123",
                issuing_state="USA",
                date_of_issue=date.today(),
                date_of_expiry=date.today()
            )
        )

    def _convert_create_response(self, document, success, message, errors=None):
        """Convert internal create response to gRPC response."""
        # Mock response object
        class CreateResponse:
            def __init__(self, document, success, message, errors) -> None:
                self.document = document
                self.success = success
                self.message = message
                self.errors = errors or []

        return CreateResponse(document, success, message, errors)

    def _convert_verify_request(self, grpc_request) -> TD2DocumentVerifyRequest:
        """Convert gRPC verify request to internal model."""
        # Mock verify request
        return TD2DocumentVerifyRequest(
            document_id=getattr(grpc_request, "document_id", None),
            verify_chip=getattr(grpc_request, "verify_chip", False),
            verify_policies=getattr(grpc_request, "verify_policies", True),
            context=getattr(grpc_request, "context", {})
        )

    def _convert_verify_response(self, result, document, success, message):
        """Convert internal verify response to gRPC response."""
        class VerifyResponse:
            def __init__(self, result, document, success, message) -> None:
                self.result = result
                self.document = document
                self.success = success
                self.message = message

        return VerifyResponse(result, document, success, message)

    def _convert_get_response(self, document, success, message):
        """Convert internal get response to gRPC response."""
        class GetResponse:
            def __init__(self, document, success, message) -> None:
                self.document = document
                self.success = success
                self.message = message

        return GetResponse(document, success, message)

    def _convert_search_request(self, grpc_request) -> TD2DocumentSearchRequest:
        """Convert gRPC search request to internal model."""
        return TD2DocumentSearchRequest(
            query=getattr(grpc_request, "query", ""),
            document_type=getattr(grpc_request, "document_type", None),
            status=getattr(grpc_request, "status", None),
            limit=getattr(grpc_request, "limit", 100),
            offset=getattr(grpc_request, "offset", 0)
        )

    def _convert_search_response(self, search_response):
        """Convert internal search response to gRPC response."""
        class SearchResponse:
            def __init__(self, documents, total_count, success, message) -> None:
                self.documents = documents
                self.total_count = total_count
                self.success = success
                self.message = message

        return SearchResponse(
            search_response.documents,
            search_response.total_count,
            search_response.success,
            search_response.message
        )

    def _convert_search_response_error(self, error_message):
        """Convert search error to gRPC response."""
        class SearchResponse:
            def __init__(self, error) -> None:
                self.documents = []
                self.total_count = 0
                self.success = False
                self.message = error

        return SearchResponse(error_message)

    def _convert_status_from_grpc(self, grpc_status):
        """Convert gRPC status enum to internal status."""
        # This would map protobuf enum values to internal enum
        status_map = {
            0: TD2Status.DRAFT,      # TD2_STATUS_UNSPECIFIED -> DRAFT
            1: TD2Status.DRAFT,      # DRAFT
            2: TD2Status.ISSUED,     # ISSUED
            3: TD2Status.ACTIVE,     # ACTIVE
            4: TD2Status.EXPIRED,    # EXPIRED
            5: TD2Status.REVOKED,    # REVOKED
            6: TD2Status.SUSPENDED   # SUSPENDED
        }
        return status_map.get(grpc_status, TD2Status.DRAFT)

    def _convert_document_type_from_grpc(self, grpc_type):
        """Convert gRPC document type enum to internal type."""
        type_map = {
            0: TD2DocumentType.ID,  # TD2_DOCUMENT_TYPE_UNSPECIFIED -> ID
            1: TD2DocumentType.ID,  # ID
            2: TD2DocumentType.AC,  # AC
            3: TD2DocumentType.IA,  # IA
            4: TD2DocumentType.IC,  # IC
            5: TD2DocumentType.IF,  # IF
            6: TD2DocumentType.IP,  # IP
            7: TD2DocumentType.IR,  # IR
            8: TD2DocumentType.IV   # IV
        }
        return type_map.get(grpc_type, TD2DocumentType.ID)

    def _convert_policy_constraints_from_grpc(self, grpc_constraints):
        """Convert gRPC policy constraints to internal model."""
        return PolicyConstraints(
            work_authorization=getattr(grpc_constraints, "work_authorization", []),
            study_authorization=getattr(grpc_constraints, "study_authorization", []),
            travel_restrictions=getattr(grpc_constraints, "travel_restrictions", []),
            max_stay_duration=getattr(grpc_constraints, "max_stay_duration", None),
            renewable=getattr(grpc_constraints, "renewable", True)
        )

    def _convert_update_status_response(self, document, success, message):
        """Convert internal update status response to gRPC response."""
        class UpdateStatusResponse:
            def __init__(self, document, success, message) -> None:
                self.document = document
                self.success = success
                self.message = message

        return UpdateStatusResponse(document, success, message)

    def _convert_issue_response(self, document, success, message, errors=None):
        """Convert internal issue response to gRPC response."""
        class IssueResponse:
            def __init__(self, document, success, message, errors) -> None:
                self.document = document
                self.success = success
                self.message = message
                self.errors = errors or []

        return IssueResponse(document, success, message, errors)

    def _convert_revoke_response(self, document, success, message):
        """Convert internal revoke response to gRPC response."""
        class RevokeResponse:
            def __init__(self, document, success, message) -> None:
                self.document = document
                self.success = success
                self.message = message

        return RevokeResponse(document, success, message)

    def _convert_renew_response(self, document, success, message):
        """Convert internal renew response to gRPC response."""
        class RenewResponse:
            def __init__(self, document, success, message) -> None:
                self.document = document
                self.success = success
                self.message = message

        return RenewResponse(document, success, message)

    def _convert_statistics_response(self, stats):
        """Convert internal statistics to gRPC response."""
        class StatisticsResponse:
            def __init__(self, stats) -> None:
                self.total_documents = stats["total_documents"]
                self.active_documents = stats["active_documents"]
                self.expired_documents = stats["expired_documents"]
                self.revoked_documents = stats["revoked_documents"]
                self.by_document_type = stats["by_document_type"]
                self.by_issuing_state = stats["by_issuing_state"]
                self.generated_at = stats["generated_at"]

        return StatisticsResponse(stats)

    def _convert_expiring_response(self, documents, total_count):
        """Convert internal expiring documents to gRPC response."""
        class ExpiringResponse:
            def __init__(self, documents, total_count) -> None:
                self.documents = documents
                self.total_count = total_count
                self.success = True
                self.message = f"Found {total_count} expiring documents"

        return ExpiringResponse(documents, total_count)


def create_td2_grpc_server(td2_service: TD2Service, port: int = 50051):
    """
    Create and configure TD-2 gRPC server.

    Args:
        td2_service: TD-2 service instance
        port: Server port

    Returns:
        Configured gRPC server
    """
    server = grpc.aio.server()

    # Add TD-2 service to server
    TD2ServiceGRPC(td2_service)

    # This would normally use generated protobuf servicer
    # server.add_TD2ServiceServicer_to_server(td2_grpc_service, server)

    # Add insecure port
    listen_addr = f"[::]:{port}"
    server.add_insecure_port(listen_addr)

    logger.info(f"TD-2 gRPC server configured on {listen_addr}")
    return server


async def serve_td2_grpc(td2_service: TD2Service, port: int = 50051) -> None:
    """
    Start TD-2 gRPC server.

    Args:
        td2_service: TD-2 service instance
        port: Server port
    """
    server = create_td2_grpc_server(td2_service, port)

    logger.info(f"Starting TD-2 gRPC server on port {port}...")
    await server.start()

    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("TD-2 gRPC server shutting down...")
        await server.stop(grace=5)
