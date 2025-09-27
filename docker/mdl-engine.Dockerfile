# Dockerfile for mdl-engine service
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
    libpq-dev \
    protobuf-compiler \
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

RUN touch /app/proto/__init__.py
RUN touch /app/src/__init__.py
RUN touch /app/src/proto/__init__.py
RUN uv pip install --system --no-cache -e .
RUN uv pip install --system grpcio

# Install dependencies after source code is copied
RUN uv pip install --system -e .

# Generate Python code from proto files using the proper compilation script
RUN cd /app && python src/compile_protos.py

# Create data directories
RUN mkdir -p /app/data

# Command to run when container starts
ENV SERVICE_NAME=mdl-engine
ENV GRPC_PORT=8085
ENV PYTHONPATH=/app

CMD ["python", "/app/src/mdl_engine/src/main.py"]