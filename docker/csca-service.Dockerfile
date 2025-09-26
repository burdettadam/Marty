# Dockerfile for csca-service
FROM python:3.10-slim

# Install system dependencies for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    cmake \
    pkg-config \
    libxml2-dev \
    libxslt1-dev \
    libxmlsec1-dev \
    swig \
    libpcsclite-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install UV (a fast Python package installer and resolver)
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir uv

# Add UV to PATH explicitly (though pip install should do this)
ENV PATH="/root/.local/bin:${PATH}"

# Copy dependency definition files
COPY pyproject.toml uv.lock /app/

# Copy the application source code required for the service
COPY proto/ /app/proto/
COPY src/ /app/src/

# Ensure src/ is treated as a Python package (if not already by source control)
# compile_protos.py will create and populate src/proto/__init__.py
RUN touch /app/src/__init__.py
RUN mkdir -p /app/src/proto && touch /app/src/proto/__init__.py

# Install Python dependencies from the lock file using UV
# This ensures all external dependencies (like PyYAML, cryptography, etc.) are installed.
RUN uv pip install --system --no-cache -e .
RUN uv pip install --system grpcio

# Compile protobufs and set up the src/proto package
RUN python /app/src/compile_protos.py

# Create data directories required by the application
RUN mkdir -p /app/data/csca/certificates \
    /app/data/csca/private_keys \
    /app/data/csca/revoked \
    /app/data/csca/metadata

# Environment variables
ENV SERVICE_NAME=csca-service
ENV GRPC_PORT=8081
ENV PYTHONPATH=/app
ENV DATA_DIR=/app/data

# Command to run when container starts
CMD ["python", "/app/src/main.py"]