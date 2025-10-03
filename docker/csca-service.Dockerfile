# Dockerfile for csca-service
# Uses shared base image to reduce duplication

ARG BASE_IMAGE=marty-base:latest
FROM ${BASE_IMAGE}

# Service-specific environment
ENV SERVICE_NAME=csca-service
ENV GRPC_PORT=8081
ENV DATA_DIR=/app/data

# Copy service-specific source code
COPY src/csca_service/ /app/src/csca_service/

# Create data directories required by the application
RUN mkdir -p /app/data/csca/certificates \
    /app/data/csca/private_keys \
    /app/data/csca/revoked \
    /app/data/csca/metadata

# Expose the service port
EXPOSE 8081

# Command to run when container starts
CMD ["python", "-m", "src.apps.csca_service"]
