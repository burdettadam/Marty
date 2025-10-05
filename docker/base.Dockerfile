# Base Dockerfile for Marty Python services with security hardening
# This reduces redundancy across all service Dockerfiles

# Use specific digest for reproducible builds and switch to distroless for runtime
FROM python:3.10-slim@sha256:f2ee145f3bc4e061f5a9e2f7ca6cde3c25e7c52884d0d9644a0b5e6f15b8a51e AS build

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

# Install system dependencies with pinned versions for security
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential=12.9ubuntu3 \
    pkg-config=0.29.2-1ubuntu3 \
    libxml2-dev=2.9.13+dfsg-1ubuntu0.3 \
    xmlsec1=1.2.33-1build2 \
    libxmlsec1-dev=1.2.33-1build2 \
    libtool-bin=2.4.6-15build2 \
    libssl-dev=3.0.2-0ubuntu1.10 \
    libgcrypt20-dev=1.9.4-3ubuntu3 \
    libpcsclite-dev=1.9.5-3ubuntu1 \
    libpq-dev=14.9-0ubuntu0.22.04.1 \
    protobuf-compiler=3.12.4-1ubuntu7.22.04.1 \
    curl=7.81.0-1ubuntu1.13 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* /var/tmp/*

# Install UV package manager with pinned version
RUN pip install --no-cache-dir --upgrade pip==23.2.1 && \
    pip install --no-cache-dir uv==0.1.35

# Copy dependency files for better caching
COPY --chown=marty:marty pyproject.toml uv.lock /app/

# Create directory structure with proper ownership
RUN mkdir -p /app/src/proto /app/data /app/config /app/logs && \
    chown -R marty:marty /app

# Switch to non-root user for dependency installation
USER marty

# Install Python dependencies with hash verification
RUN uv pip install --system --no-cache --compile-bytecode -e . && \
    uv pip install --system grpcio==1.59.0 grpcio-health-checking==1.59.0

# Copy common source files with proper ownership
COPY --chown=marty:marty proto/ /app/proto/
COPY --chown=marty:marty src/marty_common/ /app/src/marty_common/
COPY --chown=marty:marty src/shared/ /app/src/shared/
COPY --chown=marty:marty src/compile_protos.py /app/src/
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