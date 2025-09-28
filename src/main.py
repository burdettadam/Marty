"""Main module for the Marty gRPC server.

This module initializes and starts the appropriate gRPC service based on the
SERVICE_NAME environment variable.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from concurrent import futures
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Optional

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc
from grpc_health.v1.health import HealthServicer

from marty_common.config import Config as MartyConfig
from marty_common.grpc_interceptors import ExceptionToStatusInterceptor
from marty_common.grpc_logging import LoggingStreamerServicer
from marty_common.grpc_tls import build_client_credentials, configure_server_security
from marty_common.logging_config import setup_logging
from marty_common.infrastructure import (
    DatabaseManager,
    EventBusProvider,
    KeyVaultClient,
    ObjectStorageClient,
    build_key_vault_client,
)
from src.proto import common_services_pb2_grpc

# --- BEGIN DEBUG PRINTS ---
print(
    f"DEBUG: src/main.py execution started. "
    f"SERVICE_NAME='{os.environ.get('SERVICE_NAME')}', "
    f"GRPC_PORT='{os.environ.get('GRPC_PORT')}'",
    file=sys.stdout,
)
sys.stdout.flush()
print(
    f"DEBUG: src/main.py error stream test. "
    f"SERVICE_NAME='{os.environ.get('SERVICE_NAME')}', "
    f"GRPC_PORT='{os.environ.get('GRPC_PORT')}'",
    file=sys.stderr,
)
sys.stderr.flush()
# --- END DEBUG PRINTS ---

# Get service name early for logging setup
SERVICE_NAME_FOR_LOGGING = os.environ.get("SERVICE_NAME", "MartyServiceDefault")
setup_logging(service_name=SERVICE_NAME_FOR_LOGGING)

logger = logging.getLogger(__name__)

# Import the generated gRPC modules for each service
try:
    from services.certificate_lifecycle_monitor import CertificateLifecycleMonitor
    from src.proto import (
        csca_service_pb2_grpc,
        document_signer_pb2_grpc,
        dtc_engine_pb2_grpc,
        inspection_system_pb2_grpc,
        mdl_engine_pb2_grpc,
        mdoc_engine_pb2_grpc,
        passport_engine_pb2_grpc,
        trust_anchor_pb2_grpc,
    )

    logger.info("Successfully imported core gRPC modules")
except ImportError:
    logger.exception("Failed to import gRPC modules")
    logger.exception("Please ensure PYTHONPATH is set correctly and proto files are compiled")
    sys.exit(1)


def get_service_config() -> dict[str, Any]:
    """Get service configuration from environment variables.

    Returns:
        Dictionary containing service configuration including name, port,
        environment, and service discovery information.
    """
    service_name = os.environ.get("SERVICE_NAME", "unknown")
    grpc_port = int(os.environ.get("GRPC_PORT", "50051"))
    env = os.environ.get("ENV", "development")

    # Get service discovery info for other services
    service_discovery = {
        "trust_anchor": (
            f"{os.environ.get('TRUST_ANCHOR_HOST', 'trust-anchor')}:"
            f"{os.environ.get('TRUST_ANCHOR_PORT', '9080')}"
        ),
        "csca_service": (
            f"{os.environ.get('CSCA_SERVICE_HOST', 'csca-service')}:"
            f"{os.environ.get('CSCA_SERVICE_PORT', '8081')}"
        ),
        "document_signer": (
            f"{os.environ.get('DOCUMENT_SIGNER_HOST', 'document-signer')}:"
            f"{os.environ.get('DOCUMENT_SIGNER_PORT', '8082')}"
        ),
        "inspection_system": (
            f"{os.environ.get('INSPECTION_SYSTEM_HOST', 'inspection-system')}:"
            f"{os.environ.get('INSPECTION_SYSTEM_PORT', '8083')}"
        ),
        "passport_engine": (
            f"{os.environ.get('PASSPORT_ENGINE_HOST', 'passport-engine')}:"
            f"{os.environ.get('PASSPORT_ENGINE_PORT', '8084')}"
        ),
        "mdl_engine": (
            f"{os.environ.get('MDL_ENGINE_HOST', 'mdl-engine')}:"
            f"{os.environ.get('MDL_ENGINE_PORT', '50051')}"
        ),
        "mdoc_engine": (
            f"{os.environ.get('MDOC_ENGINE_HOST', 'mdoc-engine')}:"
            f"{os.environ.get('MDOC_ENGINE_PORT', '50054')}"
        ),
        "pkd_service": (
            f"{os.environ.get('PKD_SERVICE_HOST', 'pkd-service')}:"
            f"{os.environ.get('PKD_SERVICE_PORT', '9090')}"
        ),
    }

    return {
        "service_name": service_name,
        "grpc_port": grpc_port,
        "env": env,
        "service_discovery": service_discovery,
    }


def create_service_channels(
    config: dict[str, Any], tls_options: dict[str, Any]
) -> dict[str, grpc.Channel]:
    """Create gRPC channels to other services.

    Args:
        config: Service configuration dictionary.

    Returns:
        Dictionary mapping service names to gRPC channels.
    """
    channels = {}
    channel_credentials = None
    if tls_options.get("enabled"):
        channel_credentials = build_client_credentials(tls_options)

    for service_name, address in config["service_discovery"].items():
        # Don't create a channel to ourselves
        if service_name != config["service_name"].replace("-", "_"):
            logger.info(f"Creating channel to {service_name} at {address}")
            try:
                if channel_credentials is not None:
                    channels[service_name] = grpc.secure_channel(address, channel_credentials)
                else:
                    channels[service_name] = grpc.insecure_channel(address)
            except grpc.RpcError:
                logger.exception(f"Failed to create channel to {service_name}")

    return channels


def init_certificate_lifecycle_monitor(
    config: dict[str, Any],
) -> CertificateLifecycleMonitor:
    """Initialize the Certificate Lifecycle Monitor.

    Args:
        config: Service configuration dictionary.

    Returns:
        Initialized CertificateLifecycleMonitor instance.
    """
    service_name = config["service_name"]
    csca_endpoint = config["service_discovery"].get("csca_service")

    if service_name == "csca-service":
        # If we're already in the CSCA service, use localhost
        csca_endpoint = f"localhost:{config['grpc_port']}"

    config_file = Path("config") / "certificate_lifecycle_monitor.json"

    logger.info(
        f"Initializing Certificate Lifecycle Monitor with endpoint "
        f"{csca_endpoint} and config {config_file}"
    )

    return CertificateLifecycleMonitor(csca_endpoint=csca_endpoint, config_file=str(config_file))


def should_enable_cert_monitor(service_name: str) -> bool:
    """Determine if certificate lifecycle monitoring should be enabled.

    Args:
        service_name: Name of the service to check.

    Returns:
        True if certificate monitoring should be enabled, False otherwise.
    """
    cert_monitor_services = [
        "csca-service",
        "document-signer",
        "trust-anchor",
        "passport-engine",
    ]

    return service_name in cert_monitor_services


def setup_health_service(server: grpc.Server) -> HealthServicer:
    """Set up and configure the health service.

    Args:
        server: gRPC server instance.

    Returns:
        Configured HealthServicer instance.
    """
    health = HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health, server)
    health.set("", health_pb2.HealthCheckResponse.SERVING)
    return health


def setup_logging_streamer_service(server: grpc.Server, health: HealthServicer) -> None:
    """Set up the logging streamer service.

    Args:
        server: gRPC server instance.
        health: Health servicer for setting service health status.
    """
    try:
        logging_streamer_servicer = LoggingStreamerServicer()
        common_services_pb2_grpc.add_LoggingStreamerServicer_to_server(
            logging_streamer_servicer, server
        )
        logger.info("Successfully added LoggingStreamerServicer to gRPC server.")
        health.set(
            "common_services.LoggingStreamer",
            health_pb2.HealthCheckResponse.SERVING,
        )
    except Exception:
        logger.exception("Failed to add LoggingStreamerServicer")
        health.set(
            "common_services.LoggingStreamer",
            health_pb2.HealthCheckResponse.NOT_SERVING,
        )


@dataclass(slots=True)
class ServiceDependencies:
    database: DatabaseManager
    object_storage: ObjectStorageClient
    key_vault: KeyVaultClient
    event_bus: EventBusProvider
    runtime_config: MartyConfig


def build_dependencies(runtime_config: MartyConfig | None = None) -> ServiceDependencies:
    runtime_config = runtime_config or MartyConfig()
    database = DatabaseManager(runtime_config.database())
    asyncio.run(database.create_all())
    object_storage = ObjectStorageClient(runtime_config.object_storage())
    key_vault = build_key_vault_client(runtime_config.key_vault())
    event_bus = EventBusProvider(runtime_config.event_bus())
    return ServiceDependencies(
        database=database,
        object_storage=object_storage,
        key_vault=key_vault,
        event_bus=event_bus,
        runtime_config=runtime_config,
    )


def add_csca_service(
    server: grpc.Server,
    channels: dict[str, grpc.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    """Add CSCA service to the server."""
    logger.info("Adding CSCA service to server")
    from services.csca import CscaService

    csca_service_pb2_grpc.add_CscaServiceServicer_to_server(
        CscaService(channels, dependencies), server
    )
    health.set("csca.CscaService", health_pb2.HealthCheckResponse.SERVING)


def add_document_signer_service(
    server: grpc.Server,
    channels: dict[str, grpc.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    """Add Document Signer service to the server."""
    logger.info("Adding Document Signer service to server")
    from services.document_signer import DocumentSigner

    document_signer_pb2_grpc.add_DocumentSignerServicer_to_server(
        DocumentSigner(channels, dependencies), server
    )
    health.set("document_signer.DocumentSigner", health_pb2.HealthCheckResponse.SERVING)


def add_trust_anchor_service(
    server: grpc.Server,
    channels: dict[str, grpc.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    """Add Trust Anchor service to the server."""
    logger.info("Adding Trust Anchor service to server")
    from services.trust_anchor import TrustAnchor

    trust_anchor_pb2_grpc.add_TrustAnchorServicer_to_server(
        TrustAnchor(channels, dependencies), server
    )
    health.set("trust.TrustAnchor", health_pb2.HealthCheckResponse.SERVING)


def add_inspection_system_service(
    server: grpc.Server,
    channels: dict[str, grpc.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    """Add Inspection System service to the server."""
    logger.info("Adding Inspection System service to server")
    from services.inspection_system import InspectionSystem

    inspection_system_pb2_grpc.add_InspectionSystemServicer_to_server(
        InspectionSystem(channels, dependencies), server
    )
    health.set("inspection.InspectionSystem", health_pb2.HealthCheckResponse.SERVING)


def add_passport_engine_service(
    server: grpc.Server,
    channels: dict[str, grpc.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    """Add Passport Engine service to the server."""
    logger.info("Adding Passport Engine service to server")
    from services.passport_engine import PassportEngine

    passport_engine_pb2_grpc.add_PassportEngineServicer_to_server(
        PassportEngine(channels, dependencies), server
    )
    health.set("passport.PassportEngine", health_pb2.HealthCheckResponse.SERVING)


def add_mdl_engine_service(
    server: grpc.Server,
    channels: dict[str, grpc.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies | None = None,
) -> None:
    """Add MDL Engine service to the server."""
    logger.info("Adding MDL Engine service to server")
    from mdl_engine.service import MDLEngineServicer

    document_signer_channel = channels.get("document_signer")
    if not document_signer_channel:
        logger.error(
            "Document Signer channel not found for MDL Engine. "
            "MDL Engine may not function correctly."
        )
    mdl_engine_pb2_grpc.add_MDLEngineServicer_to_server(
        MDLEngineServicer(document_signer_channel), server
    )
    health.set("mdl.MDLEngine", health_pb2.HealthCheckResponse.SERVING)


def add_mdoc_engine_service(
    server: grpc.Server,
    channels: dict[str, grpc.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies | None = None,
) -> None:
    """Add MDoc Engine service to the server."""
    logger.info("Adding MDoc Engine service to server")
    from mdoc_engine.service import MDocEngineServicer

    mdoc_engine_pb2_grpc.add_MDocEngineServicer_to_server(MDocEngineServicer(channels), server)
    health.set("mdoc.MDocEngine", health_pb2.HealthCheckResponse.SERVING)


def add_pkd_service(
    server: grpc.Server,
    channels: dict[str, grpc.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    """Add PKD service to the server."""
    logger.info("Adding PKD service to server")
    from services.pkd_service import PKDService

    from src.proto import pkd_service_pb2_grpc

    pkd_service_pb2_grpc.add_PKDServiceServicer_to_server(PKDService(channels, dependencies), server)
    health.set("pkd.PKDService", health_pb2.HealthCheckResponse.SERVING)


def add_service_by_name(
    service_name: str,
    server: grpc.Server,
    channels: dict[str, grpc.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    """Add the appropriate service based on service name.

    Args:
        service_name: Name of the service to add.
        server: gRPC server instance.
        channels: Service channels dictionary.
        health: Health servicer for setting service health status.
    """
    service_map = {
        "csca-service": add_csca_service,
        "document-signer": add_document_signer_service,
        "trust-anchor": add_trust_anchor_service,
        "inspection-system": add_inspection_system_service,
        "passport-engine": add_passport_engine_service,
        "mdl-engine": add_mdl_engine_service,
        "mdoc-engine": add_mdoc_engine_service,
        "pkd-service": add_pkd_service,
    }

    service_func = service_map.get(service_name)
    if service_func:
        service_func(server, channels, health, dependencies)
    else:
        logger.warning(f"Unknown service name: {service_name}, starting empty server")


def serve() -> None:
    """Start the gRPC server with all services."""
    config = get_service_config()
    service_name = config["service_name"]
    grpc_port = config["grpc_port"]

    runtime_config = MartyConfig()
    tls_options = runtime_config.grpc_tls()

    # Create service channels
    channels = create_service_channels(config, tls_options)

    # Create the gRPC server
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        interceptors=[ExceptionToStatusInterceptor()],
    )

    # Set up health service
    health = setup_health_service(server)

    # Set up logging streamer service
    setup_logging_streamer_service(server, health)

    dependencies = build_dependencies(runtime_config)

    # Add the appropriate service based on SERVICE_NAME
    add_service_by_name(service_name, server, channels, health, dependencies)

    # Initialize certificate lifecycle monitor if needed
    cert_monitor: CertificateLifecycleMonitor | None = None
    if should_enable_cert_monitor(service_name):
        logger.info("Initializing Certificate Lifecycle Monitor")
        cert_monitor = init_certificate_lifecycle_monitor(config)

    # Start the server
    server_address = f"[::]:{grpc_port}"
    if not configure_server_security(server, server_address, tls_options):
        server.add_insecure_port(server_address)
    server.start()
    logger.info(f"Server {service_name} started on {server_address}")

    # Start certificate lifecycle monitor if initialized
    if cert_monitor:
        logger.info("Starting Certificate Lifecycle Monitor")
        cert_monitor.start()

    try:
        # Keep the server alive
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        # Stop certificate lifecycle monitor if running
        if cert_monitor:
            logger.info("Stopping Certificate Lifecycle Monitor")
            cert_monitor.stop()
        server.stop(0)


if __name__ == "__main__":
    serve()
