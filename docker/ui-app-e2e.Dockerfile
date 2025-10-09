FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Install system dependencies (minimal for E2E testing)
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    g++ \
    make \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY pyproject.toml uv.lock ./
COPY src/ ./src/
COPY proto/ ./proto/

# Install UV for dependency management
ADD --chmod=755 https://astral.sh/uv/install.sh /install.sh
RUN /install.sh && rm /install.sh

# Create __init__.py files for proper module structure
RUN touch /app/src/__init__.py
RUN mkdir -p /app/src/proto && touch /app/src/proto/__init__.py

# Install Python dependencies WITHOUT biometric extras for E2E testing
RUN ~/.local/bin/uv pip install --system --no-cache -e .
RUN ~/.local/bin/uv pip install --system grpcio
RUN ~/.local/bin/uv pip install --system grpcio-health-checking
RUN ~/.local/bin/uv pip install --system python-multipart

# Skip protobuf compilation since files are pre-generated
# The generated proto files are already in src/proto/

# Environment variables for UI
ENV SERVICE_NAME=ui-app
ENV UI_TITLE="Marty Operator Console (E2E Test)"
ENV UI_ENVIRONMENT=testing
ENV UI_PASSPORT_ENGINE_ADDR=passport-engine:9084
ENV UI_INSPECTION_SYSTEM_ADDR=inspection-system:9083
ENV UI_MDL_ENGINE_ADDR=mdl-engine:8085
ENV UI_TRUST_ANCHOR_ADDR=trust-anchor:9080
ENV UI_GRPC_TIMEOUT_SECONDS=10
ENV UI_ENABLE_MOCK_DATA=true
ENV UI_THEME=light

# Expose port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

# Command to run when container starts
CMD ["python", "-m", "uvicorn", "src.ui_app.app:app", "--host", "0.0.0.0", "--port", "9090"]
