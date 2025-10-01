# Service-specific Dockerfile template
# Uses the shared base image to minimize duplication

ARG BASE_IMAGE=marty-base:latest
FROM ${BASE_IMAGE}

# Copy service-specific source code
ARG SERVICE_NAME
COPY src/${SERVICE_NAME}/ /app/src/${SERVICE_NAME}/

# Copy any additional service-specific files
COPY src/services/ /app/src/services/

# Set service-specific environment
ENV SERVICE_NAME=${SERVICE_NAME}

# Compile protobuf files if needed
RUN cd /app && python src/compile_protos.py

# Service-specific port (can be overridden)
ARG SERVICE_PORT=50051
ENV GRPC_PORT=${SERVICE_PORT}
EXPOSE ${SERVICE_PORT}

# Run the service
CMD ["python", "-m", "marty_common.grpc_server_runner"]