# Dockerfile for trust-anchor service
FROM python:3.10-slim

# Install system dependencies for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    pkg-config \
    libxml2-dev \
    libxslt1-dev \
    libxmlsec1-dev \
    swig \
    libpcsclite-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

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

# Install dependencies after source code is copied
RUN uv pip install --system -e .
RUN uv pip install --system grpcio

# Generate Python code from proto files using our compilation script
RUN cd /app && python src/compile_protos.py

# Create data directories
RUN mkdir -p /app/data

# Command to run when container starts
ENV SERVICE_NAME=trust-anchor
ENV GRPC_PORT=8080
ENV PYTHONPATH=/app

CMD ["python", "/app/src/main.py"]