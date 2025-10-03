# Multi-stage build using base image for DTC Engine Service
FROM marty-base:latest as base

# Service-specific build stage
FROM base as dtc-engine

# Set service-specific environment variables
ENV SERVICE_NAME=dtc-engine
ENV GRPC_PORT=50054

# Copy DTC Engine service source code
COPY src/dtc_engine/ /app/src/dtc_engine/

# Copy service-specific resources
COPY src/services/dtc_engine.py /app/src/services/

# Create DTC-specific data directories
RUN mkdir -p /data/dtc/credentials /data/dtc/qr-codes

# Set working directory to DTC engine service
WORKDIR /app/src/dtc_engine

# Create a non-root user
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app /data
USER appuser

# Expose port
EXPOSE 50054

# Command to run the DTC Engine service
CMD ["python", "-m", "main"]