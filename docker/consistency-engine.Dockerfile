# Cross-Zone Consistency Engine Docker Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY pyproject.toml uv.lock ./

# Install Python dependencies
RUN pip install --no-cache-dir uv && \
    uv sync --frozen

# Copy protobuf files and generate Python stubs
COPY proto/ ./proto/
COPY src/compile_protos.py ./src/
RUN python src/compile_protos.py

# Copy source code
COPY src/ ./src/

# Copy configuration files
COPY config/ ./config/

# Create non-root user for security
RUN useradd -m -u 1000 consistency-engine && \
    chown -R consistency-engine:consistency-engine /app

USER consistency-engine

# Expose ports
EXPOSE 8080 50051

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set environment variables
ENV PYTHONPATH=/app
ENV SERVICE_NAME=consistency-engine
ENV LOG_LEVEL=INFO
ENV GRPC_PORT=50051
ENV HTTP_PORT=8080

# Default command - can be overridden
CMD ["python", "-m", "src.services.consistency_engine_server"]