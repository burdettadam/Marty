#!/usr/bin/env python3
"""
gRPC server for the Consistency Engine service.

This module provides the gRPC server implementation for the Cross-Zone
Consistency Engine, supporting both standalone gRPC serving and dual
gRPC/HTTP serving.
"""

import asyncio
import logging
import os
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import grpc
import uvicorn
from grpc import aio

from src.marty_common.observability import MetricsCollector, StructuredLogger
from src.proto import consistency_engine_pb2_grpc
from src.services.consistency_engine import ConsistencyEngine
from src.services.consistency_engine_rest_api import create_consistency_engine_app


class ConsistencyEngineServer:
    """
    Consistency Engine gRPC and HTTP server.

    Provides both gRPC and REST API endpoints for the consistency engine,
    with proper lifecycle management and graceful shutdown.
    """

    def __init__(
        self, grpc_port: int = 50051, http_port: int = 8080, enable_http: bool = True
    ) -> None:
        """Initialize the server."""
        self.grpc_port = grpc_port
        self.http_port = http_port
        self.enable_http = enable_http

        # Initialize logging and metrics
        self.logger = StructuredLogger(__name__)
        self.metrics = MetricsCollector("consistency_engine_server")

        # Initialize services
        self.consistency_engine = ConsistencyEngine()

        # Server instances
        self.grpc_server: aio.Server | None = None
        self.http_server_task: asyncio.Task | None = None

        # Shutdown event
        self.shutdown_event = asyncio.Event()

        self.logger.info(
            "Consistency Engine server initialized",
            extra={"grpc_port": grpc_port, "http_port": http_port, "enable_http": enable_http},
        )

    async def start_grpc_server(self) -> None:
        """Start the gRPC server."""
        try:
            # Create gRPC server
            self.grpc_server = aio.server(ThreadPoolExecutor(max_workers=10))

            # Add consistency engine service
            consistency_engine_pb2_grpc.add_ConsistencyEngineServicer_to_server(
                self.consistency_engine, self.grpc_server
            )

            # Configure listening port
            listen_addr = f"[::]:{self.grpc_port}"
            self.grpc_server.add_insecure_port(listen_addr)

            # Start server
            await self.grpc_server.start()

            self.logger.info("gRPC server started", extra={"address": listen_addr})

            self.metrics.gauge("grpc_server_status", 1.0)
            self.metrics.info(
                "grpc_server_info", {"port": str(self.grpc_port), "status": "running"}
            )

        except Exception as e:
            self.logger.error(f"Failed to start gRPC server: {e}", exc_info=True)
            self.metrics.gauge("grpc_server_status", 0.0)
            raise

    async def start_http_server(self) -> None:
        """Start the HTTP server."""
        if not self.enable_http:
            return

        try:
            # Create FastAPI app
            app = create_consistency_engine_app(self.consistency_engine)

            # Configure uvicorn
            config = uvicorn.Config(
                app,
                host="0.0.0.0",
                port=self.http_port,
                log_level="info",
                access_log=True,
                loop="asyncio",
            )

            # Create and run server
            server = uvicorn.Server(config)

            self.logger.info("HTTP server starting", extra={"port": self.http_port})

            # Run server in background task
            self.http_server_task = asyncio.create_task(server.serve())

            self.metrics.gauge("http_server_status", 1.0)
            self.metrics.info(
                "http_server_info", {"port": str(self.http_port), "status": "running"}
            )

        except Exception as e:
            self.logger.error(f"Failed to start HTTP server: {e}", exc_info=True)
            self.metrics.gauge("http_server_status", 0.0)
            raise

    async def start(self) -> None:
        """Start both gRPC and HTTP servers."""
        try:
            self.logger.info("Starting Consistency Engine servers")

            # Start gRPC server
            await self.start_grpc_server()

            # Start HTTP server if enabled
            if self.enable_http:
                await self.start_http_server()

            self.logger.info("All servers started successfully")
            self.metrics.increment("server_starts_total")

        except Exception as e:
            self.logger.error(f"Failed to start servers: {e}", exc_info=True)
            self.metrics.increment("server_start_errors_total")
            raise

    async def stop(self) -> None:
        """Stop all servers gracefully."""
        try:
            self.logger.info("Stopping Consistency Engine servers")

            # Signal shutdown
            self.shutdown_event.set()

            # Stop gRPC server
            if self.grpc_server:
                self.logger.info("Stopping gRPC server")
                await self.grpc_server.stop(grace=30)
                self.grpc_server = None
                self.metrics.gauge("grpc_server_status", 0.0)

            # Stop HTTP server
            if self.http_server_task:
                self.logger.info("Stopping HTTP server")
                self.http_server_task.cancel()
                try:
                    await self.http_server_task
                except asyncio.CancelledError:
                    pass
                self.http_server_task = None
                self.metrics.gauge("http_server_status", 0.0)

            self.logger.info("All servers stopped")
            self.metrics.increment("server_stops_total")

        except Exception as e:
            self.logger.error(f"Error during server shutdown: {e}", exc_info=True)
            self.metrics.increment("server_stop_errors_total")

    async def wait_for_termination(self) -> None:
        """Wait for server termination."""
        try:
            if self.grpc_server:
                await self.grpc_server.wait_for_termination()

            if self.http_server_task:
                await self.http_server_task

        except Exception as e:
            self.logger.error(f"Error waiting for termination: {e}", exc_info=True)

    async def run(self) -> None:
        """Run the server until shutdown."""
        try:
            # Start servers
            await self.start()

            # Set up signal handlers
            def signal_handler(signum, frame):
                self.logger.info(f"Received signal {signum}, initiating shutdown")
                asyncio.create_task(self.stop())

            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)

            # Wait for shutdown
            await self.shutdown_event.wait()

            # Wait for termination
            await self.wait_for_termination()

        except Exception as e:
            self.logger.error(f"Server run error: {e}", exc_info=True)
            raise
        finally:
            await self.stop()


async def main():
    """Main entry point for the server."""
    # Get configuration from environment
    grpc_port = int(os.getenv("GRPC_PORT", "50051"))
    http_port = int(os.getenv("HTTP_PORT", "8080"))
    enable_http = os.getenv("ENABLE_HTTP", "true").lower() == "true"
    log_level = os.getenv("LOG_LEVEL", "INFO")

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Create and run server
    server = ConsistencyEngineServer(
        grpc_port=grpc_port, http_port=http_port, enable_http=enable_http
    )

    try:
        await server.run()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
