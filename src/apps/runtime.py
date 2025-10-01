from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Awaitable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import grpc
from grpc import aio as grpc_aio
from grpc_health.v1 import health_pb2, health_pb2_grpc
from grpc_health.v1.health import HealthServicer

from marty_common.config import Config as MartyConfig
from marty_common.grpc_interceptors import AsyncExceptionToStatusInterceptor
from marty_common.grpc_logging import LoggingStreamerServicer
from marty_common.grpc_tls import build_client_credentials, configure_server_security
from marty_common.infrastructure import (
    DatabaseManager,
    EventBusProvider,
    KeyVaultClient,
    ObjectStorageClient,
    OutboxDispatcher,
    build_key_vault_client,
)
from marty_common.logging_config import setup_logging
from services.certificate_lifecycle_monitor import CertificateLifecycleMonitor
from src.proto import common_services_pb2_grpc

logger = logging.getLogger(__name__)


ServiceRegistrar = Callable[
    [grpc_aio.Server, dict[str, grpc_aio.Channel], HealthServicer, "ServiceDependencies"],
    None,
]


@dataclass(slots=True)
class ServiceDefinition:
    """Metadata necessary to bootstrap a Marty microservice."""

    name: str
    default_port: int
    registrar: ServiceRegistrar


@dataclass(slots=True)
class ServiceDependencies:
    database: DatabaseManager
    object_storage: ObjectStorageClient
    key_vault: KeyVaultClient
    event_bus: EventBusProvider
    runtime_config: MartyConfig
    outbox_dispatcher: OutboxDispatcher
    shutdown_hooks: list[Callable[[], Awaitable[None]]] = field(default_factory=list)

    async def shutdown(self) -> None:
        if self.shutdown_hooks:
            await asyncio.gather(
                *(hook() for hook in reversed(self.shutdown_hooks)),
                return_exceptions=True,
            )
        await self.outbox_dispatcher.stop()
        await self.event_bus.stop()
        await self.database.dispose()

    def register_shutdown_hook(self, hook: Callable[[], Awaitable[None]]) -> None:
        self.shutdown_hooks.append(hook)


async def build_dependencies_async(
    runtime_config: MartyConfig | None = None,
) -> ServiceDependencies:
    runtime_config = runtime_config or MartyConfig()
    database = DatabaseManager(runtime_config.database())
    await database.create_all()
    object_storage = ObjectStorageClient(runtime_config.object_storage())
    key_vault = build_key_vault_client(runtime_config.key_vault())
    event_bus_config = runtime_config.event_bus()
    event_bus = EventBusProvider(event_bus_config)
    outbox_dispatcher = OutboxDispatcher(database, event_bus)
    if event_bus_config.enabled:
        await outbox_dispatcher.start()
    return ServiceDependencies(
        database=database,
        object_storage=object_storage,
        key_vault=key_vault,
        event_bus=event_bus,
        runtime_config=runtime_config,
        outbox_dispatcher=outbox_dispatcher,
    )


def create_service_channels(
    config: dict[str, Any], tls_options: dict[str, Any]
) -> dict[str, grpc_aio.Channel]:
    """Create gRPC channels to other services based on discovery config."""
    channels: dict[str, grpc_aio.Channel] = {}
    channel_credentials = None
    if tls_options.get("enabled"):
        channel_credentials = build_client_credentials(tls_options)

    for service_name, address in config["service_discovery"].items():
        if service_name != config["service_name"].replace("-", "_"):
            logger.info("Creating channel to %s at %s", service_name, address)
            try:
                if channel_credentials is not None:
                    channels[service_name] = grpc_aio.secure_channel(address, channel_credentials)
                else:
                    channels[service_name] = grpc_aio.insecure_channel(address)
            except grpc.RpcError:
                logger.exception("Failed to create channel to %s", service_name)

    return channels


def get_service_config(service_name: str, default_port: int) -> dict[str, Any]:
    """Build the runtime configuration for a specific service."""
    overridden_name = os.environ.get("SERVICE_NAME")
    if overridden_name and overridden_name != service_name:
        logger.warning(
            "Ignoring SERVICE_NAME=%s because entrypoint is fixed for %s",
            overridden_name,
            service_name,
        )

    grpc_port = int(os.environ.get("GRPC_PORT", str(default_port)))
    env = os.environ.get("ENV", "development")

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


def init_certificate_lifecycle_monitor(
    config: dict[str, Any],
) -> CertificateLifecycleMonitor:
    """Initialize the Certificate Lifecycle Monitor."""
    csca_endpoint = config["service_discovery"].get("csca_service")

    if config["service_name"] == "csca-service":
        csca_endpoint = f"localhost:{config['grpc_port']}"

    config_file = Path("config") / "certificate_lifecycle_monitor.json"

    logger.info(
        "Initializing Certificate Lifecycle Monitor with endpoint %s and config %s",
        csca_endpoint,
        config_file,
    )

    return CertificateLifecycleMonitor(csca_endpoint=csca_endpoint, config_file=str(config_file))


CERT_MONITOR_SERVICES = {
    "csca-service",
    "document-signer",
    "trust-anchor",
    "passport-engine",
}


def should_enable_cert_monitor(service_name: str) -> bool:
    return service_name in CERT_MONITOR_SERVICES


def setup_health_service(server: grpc_aio.Server) -> HealthServicer:
    health = HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health, server)
    health.set("", health_pb2.HealthCheckResponse.SERVING)
    return health


def setup_logging_streamer_service(server: grpc_aio.Server, health: HealthServicer) -> None:
    try:
        logging_streamer_servicer = LoggingStreamerServicer()
        common_services_pb2_grpc.add_LoggingStreamerServicer_to_server(
            logging_streamer_servicer, server
        )
        logger.info("Added LoggingStreamerServicer to gRPC server")
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


# Individual registrar helpers -------------------------------------------------


def add_csca_service(
    server: grpc_aio.Server,
    channels: dict[str, grpc_aio.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    from services.csca import CscaService
    from src.proto import csca_service_pb2_grpc

    logger.info("Registering CSCA service")
    csca_service_pb2_grpc.add_CscaServiceServicer_to_server(
        CscaService(channels, dependencies), server
    )
    health.set("csca.CscaService", health_pb2.HealthCheckResponse.SERVING)


def add_document_signer_service(
    server: grpc_aio.Server,
    channels: dict[str, grpc_aio.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    from services.document_signer import DocumentSigner
    from src.proto import document_signer_pb2_grpc

    logger.info("Registering Document Signer service")
    document_signer_pb2_grpc.add_DocumentSignerServicer_to_server(
        DocumentSigner(channels, dependencies), server
    )
    health.set("document_signer.DocumentSigner", health_pb2.HealthCheckResponse.SERVING)


def add_trust_anchor_service(
    server: grpc_aio.Server,
    channels: dict[str, grpc_aio.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    from services.trust_anchor import TrustAnchor
    from src.proto import trust_anchor_pb2_grpc

    logger.info("Registering Trust Anchor service")
    trust_anchor_pb2_grpc.add_TrustAnchorServicer_to_server(
        TrustAnchor(channels, dependencies), server
    )
    health.set("trust.TrustAnchor", health_pb2.HealthCheckResponse.SERVING)


def add_inspection_system_service(
    server: grpc_aio.Server,
    channels: dict[str, grpc_aio.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    from services.inspection_system import InspectionSystem
    from src.proto import inspection_system_pb2_grpc

    logger.info("Registering Inspection System service")
    inspection_system_pb2_grpc.add_InspectionSystemServicer_to_server(
        InspectionSystem(channels, dependencies), server
    )
    health.set("inspection.InspectionSystem", health_pb2.HealthCheckResponse.SERVING)


def add_passport_engine_service(
    server: grpc_aio.Server,
    channels: dict[str, grpc_aio.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    from services.passport_engine import PassportEngine
    from src.proto import passport_engine_pb2_grpc

    logger.info("Registering Passport Engine service")
    passport_engine_pb2_grpc.add_PassportEngineServicer_to_server(
        PassportEngine(channels, dependencies), server
    )
    health.set("passport.PassportEngine", health_pb2.HealthCheckResponse.SERVING)


def add_mdl_engine_service(
    server: grpc_aio.Server,
    channels: dict[str, grpc_aio.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies | None = None,
) -> None:
    from mdl_engine.service import MDLEngineServicer
    from src.proto import mdl_engine_pb2_grpc

    logger.info("Registering MDL Engine service")
    document_signer_channel = channels.get("document_signer")
    if not document_signer_channel:
        logger.error(
            "Document Signer channel not found for MDL Engine. MDL Engine may not function correctly."
        )
    mdl_engine_pb2_grpc.add_MDLEngineServicer_to_server(
        MDLEngineServicer(document_signer_channel), server
    )
    health.set("mdl.MDLEngine", health_pb2.HealthCheckResponse.SERVING)


def add_mdoc_engine_service(
    server: grpc_aio.Server,
    channels: dict[str, grpc_aio.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies | None = None,
) -> None:
    from mdoc_engine.service import MDocEngineServicer
    from src.proto import mdoc_engine_pb2_grpc

    logger.info("Registering MDoc Engine service")
    mdoc_engine_pb2_grpc.add_MDocEngineServicer_to_server(MDocEngineServicer(channels), server)
    health.set("mdoc.MDocEngine", health_pb2.HealthCheckResponse.SERVING)


def add_pkd_service(
    server: grpc_aio.Server,
    channels: dict[str, grpc_aio.Channel],
    health: HealthServicer,
    dependencies: ServiceDependencies,
) -> None:
    from services.pkd_service import PKDService
    from src.proto import pkd_service_pb2_grpc

    logger.info("Registering PKD service")
    pkd_service_pb2_grpc.add_PKDServiceServicer_to_server(
        PKDService(channels, dependencies), server
    )
    health.set("pkd.PKDService", health_pb2.HealthCheckResponse.SERVING)


SERVICE_REGISTRARS: dict[str, ServiceRegistrar] = {
    "csca-service": add_csca_service,
    "document-signer": add_document_signer_service,
    "trust-anchor": add_trust_anchor_service,
    "inspection-system": add_inspection_system_service,
    "passport-engine": add_passport_engine_service,
    "mdl-engine": add_mdl_engine_service,
    "mdoc-engine": add_mdoc_engine_service,
    "pkd-service": add_pkd_service,
}

SERVICE_DEFAULT_PORTS: dict[str, int] = {
    "csca-service": 8081,
    "document-signer": 8082,
    "trust-anchor": 9080,
    "inspection-system": 8083,
    "passport-engine": 8084,
    "mdl-engine": 8085,
    "mdoc-engine": 8086,
    "pkd-service": 9090,
}

SERVICE_DEFINITIONS: dict[str, ServiceDefinition] = {
    name: ServiceDefinition(
        name=name, default_port=SERVICE_DEFAULT_PORTS[name], registrar=registrar
    )
    for name, registrar in SERVICE_REGISTRARS.items()
}


async def serve_service_async(
    service: ServiceDefinition,
    *,
    runtime_config: MartyConfig | None = None,
) -> None:
    """Async entrypoint for a dedicated microservice."""
    setup_logging(service.name)

    config = get_service_config(service.name, service.default_port)
    logger.info(
        "Starting %s with config: env=%s port=%s", service.name, config["env"], config["grpc_port"]
    )

    runtime_config = runtime_config or MartyConfig()
    tls_options = runtime_config.grpc_tls()

    channels = create_service_channels(config, tls_options)
    server = grpc_aio.server(interceptors=[AsyncExceptionToStatusInterceptor()])

    health = setup_health_service(server)
    setup_logging_streamer_service(server, health)

    dependencies = await build_dependencies_async(runtime_config)

    registrar = SERVICE_REGISTRARS.get(service.name)
    if not registrar:
        msg = f"Unknown service name: {service.name}"
        raise ValueError(msg)

    registrar(server, channels, health, dependencies)

    cert_monitor: CertificateLifecycleMonitor | None = None
    if should_enable_cert_monitor(service.name):
        cert_monitor = init_certificate_lifecycle_monitor(config)

    server_address = f"[::]:{config['grpc_port']}"
    if not configure_server_security(server, server_address, tls_options):
        server.add_insecure_port(server_address)

    server_started = False
    try:
        await server.start()
        server_started = True
        logger.info("%s gRPC server started on %s", service.name, server_address)

        if cert_monitor:
            cert_monitor.start()
            logger.info("Certificate Lifecycle Monitor started")

        await server.wait_for_termination()
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutdown signal received; terminating %s", service.name)
    finally:
        if cert_monitor:
            cert_monitor.stop()
            logger.info("Certificate Lifecycle Monitor stopped")

        if server_started:
            await server.stop(grace=0)

        await asyncio.gather(
            *(channel.close() for channel in channels.values()),
            return_exceptions=True,
        )

        await dependencies.shutdown()


def serve_service(service: ServiceDefinition) -> None:
    """Start the service using asyncio."""
    asyncio.run(serve_service_async(service))


__all__ = [
    "SERVICE_DEFAULT_PORTS",
    "SERVICE_DEFINITIONS",
    "ServiceDefinition",
    "ServiceDependencies",
    "build_dependencies_async",
    "serve_service",
    "serve_service_async",
]
