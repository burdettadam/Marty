"""
gRPC Service Factory for Marty services.

This module provides a comprehensive factory pattern for creating, configuring,
and running gRPC services with consistent patterns across all Marty services.
It builds on the existing BaseGrpcService and base configuration infrastructure
to provide even more DRY patterns for service creation.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from abc import ABC, abstractmethod
from concurrent import futures
from pathlib import Path
from typing import Any, Callable, Protocol

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc
from grpc_health.v1.health import HealthServicer
from grpc_reflection.v1alpha import reflection

from marty_common.base_config import BaseServiceConfig, GRPCServiceConfig, create_service_config
from marty_common.grpc_logging import LoggingStreamerServicer
from marty_common.grpc_server import GrpcServerConfig, MartyGrpcServer
from marty_common.logging_config import setup_logging, get_logger
from src.proto import common_services_pb2_grpc

logger = get_logger(__name__)


class ServicerFactoryProtocol(Protocol):
    """Protocol for servicer factory functions."""
    
    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Create a servicer instance."""
        ...


class ServiceRegistrationProtocol(Protocol):
    """Protocol for service registration functions (add_*Servicer_to_server)."""
    
    def __call__(self, servicer: Any, server: grpc.Server) -> None:
        """Add servicer to gRPC server."""
        ...


class ServiceDefinition:
    """Definition of a gRPC service for factory creation."""
    
    def __init__(
        self,
        name: str,
        servicer_factory: ServicerFactoryProtocol,
        registration_func: ServiceRegistrationProtocol,
        health_service_name: str | None = None,
        dependencies: dict[str, Any] | None = None,
        priority: int = 100,
    ) -> None:
        """Initialize service definition.
        
        Args:
            name: Service name for logging and identification
            servicer_factory: Function that creates servicer instances
            registration_func: Function to register servicer with server
            health_service_name: Name for health check service (optional)
            dependencies: Dependencies required by the servicer (optional)
            priority: Registration priority (lower numbers first)
        """
        self.name = name
        self.servicer_factory = servicer_factory
        self.registration_func = registration_func
        self.health_service_name = health_service_name or name
        self.dependencies = dependencies or {}
        self.priority = priority
    
    def create_servicer(self, **kwargs: Any) -> Any:
        """Create servicer instance with merged dependencies and kwargs."""
        merged_kwargs = {**self.dependencies, **kwargs}
        return self.servicer_factory(**merged_kwargs)
    
    def register_servicer(self, servicer: Any, server: grpc.Server) -> None:
        """Register servicer with the gRPC server."""
        self.registration_func(servicer, server)


class GRPCServiceFactory:
    """Factory for creating and managing gRPC services with DRY patterns."""
    
    def __init__(self, config: BaseServiceConfig | GRPCServiceConfig) -> None:
        """Initialize the service factory with configuration.
        
        Args:
            config: Service configuration (BaseServiceConfig or GRPCServiceConfig)
        """
        self.config = config
        self.services: list[ServiceDefinition] = []
        self.server: grpc.Server | None = None
        self.health_servicer: HealthServicer | None = None
        self._running = False
        self._shutdown_requested = False
        
        # Set up logging
        config.setup_logging()
        self.logger = get_logger(f"{self.__class__.__name__}.{config.service_name}")
    
    def register_service(
        self,
        name: str,
        servicer_factory: ServicerFactoryProtocol,
        registration_func: ServiceRegistrationProtocol,
        health_service_name: str | None = None,
        dependencies: dict[str, Any] | None = None,
        priority: int = 100,
    ) -> GRPCServiceFactory:
        """Register a service with the factory.
        
        Args:
            name: Service name
            servicer_factory: Function to create servicer instance
            registration_func: Function to register servicer with server
            health_service_name: Name for health check (optional)
            dependencies: Service dependencies (optional)
            priority: Registration priority (optional)
            
        Returns:
            Self for method chaining
        """
        service_def = ServiceDefinition(
            name=name,
            servicer_factory=servicer_factory,
            registration_func=registration_func,
            health_service_name=health_service_name,
            dependencies=dependencies,
            priority=priority,
        )
        self.services.append(service_def)
        self.logger.info(f"Registered service: {name}")
        return self
    
    def register_standard_services(self) -> GRPCServiceFactory:
        """Register standard Marty services (health check, logging streamer).
        
        Returns:
            Self for method chaining
        """
        # Health check service (highest priority)
        self.register_service(
            name="health_check",
            servicer_factory=lambda: HealthServicer(),
            registration_func=health_pb2_grpc.add_HealthServicer_to_server,
            health_service_name="grpc.health.v1.Health",
            priority=1,
        )
        
        # Logging streamer service
        self.register_service(
            name="logging_streamer",
            servicer_factory=lambda: LoggingStreamerServicer(),
            registration_func=common_services_pb2_grpc.add_LoggingStreamerServicer_to_server,
            health_service_name="common_services.LoggingStreamer",
            priority=10,
        )
        
        return self
    
    def create_server(self, **kwargs: Any) -> grpc.Server:
        """Create and configure the gRPC server.
        
        Args:
            **kwargs: Additional kwargs for servicer creation
            
        Returns:
            Configured gRPC server
        """
        grpc_config = self.config.get_grpc_config()
        
        # Create server with options from configuration
        server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=grpc_config["max_workers"]),
            options=grpc_config.get("options", [])
        )
        
        # Sort services by priority
        sorted_services = sorted(self.services, key=lambda s: s.priority)
        
        # Register all services
        for service_def in sorted_services:
            try:
                servicer = service_def.create_servicer(**kwargs)
                service_def.register_servicer(servicer, server)
                
                # Set health status if health servicer exists
                if hasattr(self, "_health_servicer") and self._health_servicer:
                    self._health_servicer.set(
                        service_def.health_service_name,
                        health_pb2.HealthCheckResponse.SERVING
                    )
                
                self.logger.info(f"Successfully registered service: {service_def.name}")
                
            except Exception as e:
                self.logger.error(
                    f"Failed to register service {service_def.name}: {e}",
                    exc_info=True
                )
                
                # Set health status to NOT_SERVING if health servicer exists
                if hasattr(self, "_health_servicer") and self._health_servicer:
                    self._health_servicer.set(
                        service_def.health_service_name,
                        health_pb2.HealthCheckResponse.NOT_SERVING
                    )
        
        # Enable reflection if configured
        if getattr(self.config, "reflection_enabled", True):
            service_names = [service.health_service_name for service in sorted_services]
            service_names.append("grpc.reflection.v1alpha.ServerReflection")
            reflection.enable_server_reflection(service_names, server)
            self.logger.info("Enabled gRPC reflection")
        
        # Add server port
        server_address = f"[::]:{grpc_config['port']}"
        
        if self.config.tls_enabled:
            # Configure TLS
            tls_config = self.config.get_tls_config()
            if all(tls_config.get(key) for key in ["cert_file", "key_file"]):
                with Path(tls_config["cert_file"]).open("rb") as cert_file:
                    cert_data = cert_file.read()
                with Path(tls_config["key_file"]).open("rb") as key_file:
                    key_data = key_file.read()
                
                credentials = grpc.ssl_server_credentials([(key_data, cert_data)])
                server.add_secure_port(server_address, credentials)
                self.logger.info(f"Configured secure server on {server_address}")
            else:
                self.logger.warning("TLS enabled but cert/key files not provided, using insecure port")
                server.add_insecure_port(server_address)
        else:
            server.add_insecure_port(server_address)
            self.logger.info(f"Configured insecure server on {server_address}")
        
        self.server = server
        return server
    
    def start(self, **kwargs: Any) -> None:
        """Start the gRPC server.
        
        Args:
            **kwargs: Additional kwargs for servicer creation
        """
        if self._running:
            self.logger.warning("Server is already running")
            return
        
        self.logger.info(f"Starting {self.config.service_name} gRPC server...")
        
        # Create server if not already created
        if not self.server:
            self.create_server(**kwargs)
        
        # Set up signal handlers
        self._setup_signal_handlers()
        
        # Start the server
        self.server.start()
        self._running = True
        
        self.logger.info(
            f"{self.config.service_name} gRPC server started on port {self.config.grpc_port}"
        )
    
    def serve(self, **kwargs: Any) -> None:
        """Start the server and wait for termination.
        
        Args:
            **kwargs: Additional kwargs for servicer creation
        """
        self.start(**kwargs)
        
        try:
            self.server.wait_for_termination()
        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt")
        except Exception as e:
            self.logger.error(f"Server error: {e}", exc_info=True)
        finally:
            self.stop()
    
    def stop(self, grace_period: int = 30) -> None:
        """Stop the gRPC server gracefully.
        
        Args:
            grace_period: Grace period in seconds for shutdown
        """
        if not self._running:
            return
        
        self.logger.info("Stopping gRPC server...")
        
        if self.server:
            self.server.stop(grace_period)
        
        self._running = False
        self.logger.info("gRPC server stopped")
    
    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        def signal_handler(signum: int, frame: Any) -> None:
            self.logger.info(f"Received signal {signum}, initiating graceful shutdown")
            self._shutdown_requested = True
            self.stop()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)


class ServiceRegistry:
    """Registry for managing service definitions across the platform."""
    
    def __init__(self) -> None:
        self._services: dict[str, ServiceDefinition] = {}
    
    def register(
        self,
        name: str,
        servicer_factory: ServicerFactoryProtocol,
        registration_func: ServiceRegistrationProtocol,
        **kwargs: Any
    ) -> None:
        """Register a service in the global registry."""
        service_def = ServiceDefinition(
            name=name,
            servicer_factory=servicer_factory,
            registration_func=registration_func,
            **kwargs
        )
        self._services[name] = service_def
    
    def get(self, name: str) -> ServiceDefinition | None:
        """Get a service definition by name."""
        return self._services.get(name)
    
    def get_all(self) -> dict[str, ServiceDefinition]:
        """Get all registered services."""
        return self._services.copy()


# Global service registry
service_registry = ServiceRegistry()


def create_grpc_service_factory(
    service_name: str,
    config_type: str = "grpc",
    **config_kwargs: Any
) -> GRPCServiceFactory:
    """Create a gRPC service factory with standard configuration.
    
    Args:
        service_name: Name of the service
        config_type: Type of configuration ("grpc" or "hybrid")
        **config_kwargs: Additional configuration parameters
        
    Returns:
        Configured GRPCServiceFactory instance
    """
    config = create_service_config(
        service_type=config_type,
        service_name=service_name,
        **config_kwargs
    )
    
    factory = GRPCServiceFactory(config)
    factory.register_standard_services()
    
    return factory


def run_single_service(
    service_name: str,
    servicer_factory: ServicerFactoryProtocol,
    registration_func: ServiceRegistrationProtocol,
    config_kwargs: dict[str, Any] | None = None,
    servicer_kwargs: dict[str, Any] | None = None,
) -> None:
    """Run a single gRPC service with minimal configuration.
    
    This is a convenience function for simple service entry points.
    
    Args:
        service_name: Name of the service
        servicer_factory: Function to create the servicer
        registration_func: Function to register the servicer
        config_kwargs: Configuration parameters (optional)
        servicer_kwargs: Servicer creation parameters (optional)
    """
    config_kwargs = config_kwargs or {}
    servicer_kwargs = servicer_kwargs or {}
    
    factory = create_grpc_service_factory(service_name, **config_kwargs)
    factory.register_service(
        name=service_name,
        servicer_factory=servicer_factory,
        registration_func=registration_func,
        dependencies=servicer_kwargs,
    )
    factory.serve()


def register_service_globally(
    name: str,
    servicer_factory: ServicerFactoryProtocol,
    registration_func: ServiceRegistrationProtocol,
    **kwargs: Any
) -> None:
    """Register a service in the global registry for reuse.
    
    Args:
        name: Service name
        servicer_factory: Function to create servicer
        registration_func: Function to register servicer
        **kwargs: Additional service definition parameters
    """
    service_registry.register(
        name=name,
        servicer_factory=servicer_factory,
        registration_func=registration_func,
        **kwargs
    )


# Decorator for easy service registration
def grpc_service(
    name: str,
    registration_func: ServiceRegistrationProtocol,
    **service_kwargs: Any
):
    """Decorator to register a class as a gRPC service.
    
    Args:
        name: Service name
        registration_func: Function to register the servicer
        **service_kwargs: Additional service definition parameters
    """
    def decorator(cls: type) -> type:
        def factory(**kwargs: Any) -> Any:
            return cls(**kwargs)
        
        register_service_globally(
            name=name,
            servicer_factory=factory,
            registration_func=registration_func,
            **service_kwargs
        )
        return cls
    
    return decorator