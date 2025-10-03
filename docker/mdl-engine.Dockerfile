# Dockerfile for mdl-engine service
# Uses shared base image to reduce duplication

ARG BASE_IMAGE=marty-base:latest
FROM ${BASE_IMAGE}

# Service-specific environment
ENV SERVICE_NAME=mdl-engine
ENV GRPC_PORT=8085

# Copy service-specific source code
COPY src/mdl_engine/ /app/src/mdl_engine/

# Expose the service port
EXPOSE 8085

# Command to run when container starts
CMD ["python", "-m", "src.apps.mdl_engine"]
