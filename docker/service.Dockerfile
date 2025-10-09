# Hardened Service-specific Dockerfile template
# Uses the shared base image to minimize duplication and security vulnerabilities

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

# Security: Ensure we're running as non-root user (inherited from base)
USER 1000:1000

# Copy service-specific source code with proper ownership
COPY --chown=1000:1000 src/${SERVICE_NAME}/ /app/src/${SERVICE_NAME}/

# Copy additional common directories
COPY --chown=1000:1000 src/services/ /app/src/services/
COPY --chown=1000:1000 src/apps/ /app/src/apps/

# Security: Make files read-only to prevent tampering
RUN find /app -type f -exec chmod 444 {} \; && \
    find /app -type d -exec chmod 555 {} \; && \
    chmod 755 /app/logs /app/data  # Keep data directories writable

# Compile protobuf files if needed (as non-root user)
RUN cd /app && python src/compile_protos.py

# Security labels for runtime
LABEL security.non-root="true"
LABEL security.readonly-rootfs="recommended"
LABEL security.capabilities="NONE"

# Expose service port (metadata only)
EXPOSE ${SERVICE_PORT}

# Health check specific to service
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/grpc_health_probe", "-addr=localhost:${SERVICE_PORT}"]
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
