FROM python:3.11-slim as builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements
COPY pyproject.toml uv.lock ./

# Install Python dependencies
RUN pip install --no-cache-dir uv && \
    uv pip install --no-cache-dir -r uv.lock

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user
RUN groupadd -r trustsvc && useradd -r -g trustsvc trustsvc

# Set working directory
WORKDIR /app

# Copy application code
COPY src/ src/
COPY config/ config/
COPY data/ data/

# Create directories and set permissions
RUN mkdir -p /app/logs /app/data && \
    chown -R trustsvc:trustsvc /app

# Switch to non-root user
USER trustsvc

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/admin/status || exit 1

# Environment variables
ENV PYTHONPATH="/app" \
    PYTHONUNBUFFERED=1 \
    TRUST_SERVICE_HOST=0.0.0.0 \
    TRUST_SERVICE_PORT=8080 \
    TRUST_SERVICE_LOG_LEVEL=INFO

# Expose port
EXPOSE 8080

# Default command
CMD ["python", "-m", "uvicorn", "src.trust_svc.api:app", "--host", "0.0.0.0", "--port", "8080"]