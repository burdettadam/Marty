# Dockerfile for passport-engine service
# Uses shared base image to reduce duplication

ARG BASE_IMAGE=marty-base:latest
FROM ${BASE_IMAGE}

# Service-specific environment
ENV SERVICE_NAME=passport-engine
ENV GRPC_PORT=8084

# Copy service-specific source code
COPY src/passport_engine/ /app/src/passport_engine/

# Expose the service port
EXPOSE 8084

# Command to run when container starts
CMD ["python", "-m", "src.apps.passport_engine"]
