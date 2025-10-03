# Service-specific Dockerfile template
# Uses the shared base image to minimize duplication

ARG BASE_IMAGE=marty-base:latest
FROM ${BASE_IMAGE}

# Build arguments
ARG SERVICE_NAME
ARG SERVICE_PORT=50051
ARG SERVICE_MODULE

# Set service-specific environment
ENV SERVICE_NAME=${SERVICE_NAME}
ENV GRPC_PORT=${SERVICE_PORT}
ENV SERVICE_MODULE=${SERVICE_MODULE:-${SERVICE_NAME}}

# Copy service-specific source code
COPY src/${SERVICE_NAME}/ /app/src/${SERVICE_NAME}/

# Copy additional common directories
COPY src/services/ /app/src/services/
COPY src/apps/ /app/src/apps/

# Compile protobuf files if needed
RUN cd /app && python src/compile_protos.py

# Expose service port
EXPOSE ${SERVICE_PORT}

# Create entrypoint script for flexibility
RUN echo '#!/bin/bash\n\
set -e\n\
if [ -n "$SERVICE_MODULE" ]; then\n\
    exec python -m "src.apps.${SERVICE_MODULE}"\n\
elif [ -n "$SERVICE_NAME" ]; then\n\
    exec python -m "src.apps.${SERVICE_NAME}"\n\
else\n\
    exec python src/main.py\n\
fi' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Run the service
CMD ["/app/entrypoint.sh"]