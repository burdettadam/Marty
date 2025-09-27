# Dockerfile for dtc-engine service
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
    protobuf-compiler \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (for better caching)
COPY pyproject.toml uv.lock /app/
RUN pip install --no-cache-dir uv && \
    uv pip install --no-cache-dir --system -e . && \
    uv pip install --system grpcio

# Copy just the necessary project files
COPY proto/ /app/proto/
COPY src/dtc_engine/dtc-engine/src/ /app/src/dtc_engine/src/
COPY src/proto/ /app/src/proto/
COPY src/marty_common/ /app/src/marty_common/
COPY src/services/ /app/src/services/
COPY src/shared/ /app/src/shared/
COPY src/compile_protos.py /app/src/

# Copy application-specific configuration
COPY config/production.yaml /app/config/production.yaml

# Create necessary directories
RUN mkdir -p /app/data

# Compile protobuf files
RUN cd /app/src && python compile_protos.py

# Expose the gRPC port
EXPOSE 8087

# Set environment variables
ENV PYTHONPATH=/app
ENV SERVICE_NAME=dtc-engine
ENV DATA_DIR=/app/data
ENV GRPC_PORT=8087

# Run the service
CMD ["python", "-u", "/app/src/dtc_engine/src/main.py"]