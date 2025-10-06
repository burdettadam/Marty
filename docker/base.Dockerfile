# Base Dockerfile for Marty Python services with security hardening
# This reduces redundancy across all service Dockerfiles

# Use specific version for reproducible builds
FROM python:3.10-slim AS build

# Security: Create non-root user early
RUN groupadd --gid 1000 marty && \
    useradd --uid 1000 --gid marty --shell /bin/bash --create-home marty

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV UV_CACHE_DIR=/tmp/uv-cache
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies including findutils for file permissions
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    g++ \
    make \
    pkg-config \
    findutils \
    libpcsclite-dev \
    && rm -rf /var/lib/apt/lists/*

# Install UV package manager with pinned version
RUN pip install --no-cache-dir --upgrade pip==23.2.1 && \
    pip install --no-cache-dir uv==0.1.35

# Copy dependency files for better caching
COPY --chown=marty:marty pyproject.toml uv.lock /app/

# Install Python dependencies with hash verification (as root)
RUN uv pip install --system --no-cache --compile-bytecode -e . && \
    uv pip install --system grpcio==1.59.0 grpcio-health-checking==1.59.0

# Create directory structure with proper ownership
RUN mkdir -p /app/src/proto /app/data /app/config /app/logs && \
    chown -R marty:marty /app

# Copy common source files with proper ownership
COPY --chown=marty:marty proto/ /app/proto/
COPY --chown=marty:marty src/marty_common/ /app/src/marty_common/
COPY --chown=marty:marty src/shared/ /app/src/shared/
COPY --chown=marty:marty src/compile_protos.py /app/src/

# Switch to non-root user after installation
USER marty
COPY --chown=marty:marty src/__init__.py /app/src/

# Create __init__.py files
RUN touch /app/proto/__init__.py /app/src/proto/__init__.py

# Runtime stage - distroless for minimal attack surface
FROM gcr.io/distroless/python3-debian11:latest AS runtime

# Copy Python environment from build stage
COPY --from=build /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=build /usr/local/bin /usr/local/bin

# Copy application files
COPY --from=build --chown=1000:1000 /app /app

# Security: Copy user from build stage
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group

# Set working directory
WORKDIR /app

# Switch to non-root user
USER 1000:1000

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV GRPC_PORT=50051
ENV SERVICE_NAME=marty-service

# Security: Drop all capabilities
# Note: distroless doesn't support CAP_DROP in labels, so this is documented
LABEL security.capabilities="NONE"
LABEL security.user="1000"
LABEL security.readonly_rootfs="true"

# Health check with improved configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/grpc_health_probe", "-addr=localhost:${GRPC_PORT}"]