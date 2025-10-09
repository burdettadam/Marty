# Multi-stage build using base image for PKD Service
FROM marty-base:latest as base

# Service-specific build stage
FROM base as pkd-service

# Set service-specific environment variables
ENV SERVICE_NAME=pkd-service
ENV GRPC_PORT=50052

# Copy PKD service source code
COPY src/pkd_service/ /app/src/pkd_service/

# Create PKD-specific data directories
RUN mkdir -p /data/pkd/masterlist /data/pkd/dsclist /data/pkd/crl

# Install PKD-specific dependencies if any
# (Currently inherits all dependencies from base)

# Set working directory to PKD service
WORKDIR /app/src/pkd_service

# Create a non-root user
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app /data
USER appuser

# Expose port
EXPOSE 8000

# Command to run the PKD service
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
