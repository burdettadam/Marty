# Base Dockerfile for Marty Python services
# This reduces redundancy across all service Dockerfiles

FROM python:3.10-slim

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV UV_CACHE_DIR=/tmp/uv-cache

WORKDIR /app

# Install system dependencies common to all services
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libxml2-dev \
    xmlsec1 \
    libxmlsec1-dev \
    libtool-bin \
    libssl-dev \
    libgcrypt20-dev \
    libpcsclite-dev \
    libpq-dev \
    protobuf-compiler \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install UV package manager
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir uv

# Copy dependency files for better caching
COPY pyproject.toml uv.lock /app/

# Create directory structure
RUN mkdir -p /app/src/proto /app/data /app/config

# Install Python dependencies
RUN uv pip install --system --no-cache -e . && \
    uv pip install --system grpcio grpcio-health-checking

# Copy common source files
COPY proto/ /app/proto/
COPY src/marty_common/ /app/src/marty_common/
COPY src/shared/ /app/src/shared/
COPY src/compile_protos.py /app/src/
COPY src/__init__.py /app/src/

# Create __init__.py files
RUN touch /app/proto/__init__.py /app/src/proto/__init__.py

# Default port and service name (can be overridden)
ENV GRPC_PORT=50051
ENV SERVICE_NAME=marty-service

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD grpc_health_probe -addr=localhost:${GRPC_PORT} || exit 1