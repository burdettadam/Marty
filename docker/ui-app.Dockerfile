FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    g++ \
    make \
    pkg-config \
    libpcsclite-dev \
    swig \
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

# Install Python dependencies from the lock file using UV
RUN ~/.local/bin/uv pip install --system --no-cache -e .
RUN ~/.local/bin/uv pip install --system grpcio

# Compile protobufs and set up the src/proto package
RUN python /app/src/compile_protos.py

# Environment variables for UI
ENV SERVICE_NAME=ui-app
ENV UI_TITLE="Marty Operator Console"
ENV UI_ENVIRONMENT=production
ENV UI_PASSPORT_ENGINE_ADDR=passport-engine:8084
ENV UI_INSPECTION_SYSTEM_ADDR=inspection-system:8083
ENV UI_MDL_ENGINE_ADDR=mdl-engine:8085
ENV UI_TRUST_ANCHOR_ADDR=trust-anchor:8080
ENV UI_GRPC_TIMEOUT_SECONDS=10
ENV UI_ENABLE_MOCK_DATA=false
ENV UI_THEME=light

# Expose port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8090/health || exit 1

# Command to run when container starts
CMD ["python", "-m", "uvicorn", "src.ui_app.app:app", "--host", "0.0.0.0", "--port", "8090"]