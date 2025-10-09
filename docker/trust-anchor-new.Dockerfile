# Multi-stage build using base image for Trust Anchor Service
FROM marty-base:latest as base

# Service-specific build stage
FROM base as trust-anchor

# Set service-specific environment variables
ENV SERVICE_NAME=trust-anchor
ENV GRPC_PORT=50053

# Copy Trust Anchor service source code
COPY src/trust_anchor/ /app/src/trust_anchor/

# Create trust anchor specific data directories
RUN mkdir -p /data/trust/anchors /data/trust/certificates

# Set working directory to trust anchor service
WORKDIR /app/src/trust_anchor

# Create a non-root user
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app /data
USER appuser

# Expose port
EXPOSE 50053

# Command to run the Trust Anchor service
CMD ["python", "-m", "app.main"]
