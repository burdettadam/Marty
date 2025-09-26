# Dockerfile for passport-engine service
FROM python:3.10-slim

WORKDIR /app

# Install build dependencies
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
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock /app/

# Install UV
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir uv

# Create the proto directory structure
RUN mkdir -p /app/src/proto

# Copy the proto files
COPY proto/ /app/proto/

# Copy the source code
COPY src/ /app/src/

# Make directories Python packages
RUN touch /app/proto/__init__.py
RUN touch /app/src/__init__.py
RUN touch /app/src/proto/__init__.py

# Install Python dependencies using uv
RUN uv pip install --system --no-cache -e .
RUN uv pip install --system grpcio
RUN uv pip install --system grpcio-health-checking

# Skip protobuf compilation since files are pre-generated
# The generated proto files are already in src/proto/

# Create data directories
RUN mkdir -p /app/data

# Command to run when container starts
ENV SERVICE_NAME=passport-engine
ENV GRPC_PORT=9084
ENV PYTHONPATH=/app

CMD ["python", "/app/src/main.py"]