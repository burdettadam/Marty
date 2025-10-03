# Template Dockerfile for Marty services using base image
# Copy this file and customize for your specific service

# Multi-stage build using base image
FROM marty-base:latest AS base

# Service-specific build stage  
FROM base AS service-name

# Set service-specific environment variables
ENV SERVICE_NAME=your-service-name
ENV GRPC_PORT=50055

# Copy service source code
COPY src/your_service/ /app/src/your_service/

# Create service-specific data directories (customize as needed)
RUN mkdir -p /data/your_service

# Install any service-specific dependencies (if needed)
# RUN uv pip install --system your-specific-dependency

# Set working directory to your service
WORKDIR /app/src/your_service

# Create a non-root user for security
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app /data
USER appuser

# Expose service port
EXPOSE ${GRPC_PORT}

# Command to run your service (customize as needed)
CMD ["python", "-m", "app.main"]