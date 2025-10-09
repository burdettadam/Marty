# Service.Dockerfile - Simplified version for Microsoft demo without permission changes
# Stage 1: Development/build dependencies
FROM marty-base:latest AS build

ARG SERVICE_NAME
ENV SERVICE_NAME=${SERVICE_NAME}

# Create application directories
RUN mkdir -p /app/logs /app/data

# Copy service-specific source code
COPY --chown=1000:1000 src/${SERVICE_NAME}/ /app/src/${SERVICE_NAME}/
COPY --chown=1000:1000 src/services/ /app/src/services/
COPY --chown=1000:1000 src/apps/ /app/src/apps/

# Compile protobuf files if needed (as non-root user)
RUN cd /app && python src/compile_protos.py

# === Runtime Stage ===
FROM marty-base:latest AS runtime

ARG SERVICE_NAME
ENV SERVICE_NAME=${SERVICE_NAME}

# Copy from build stage
COPY --from=build --chown=1000:1000 /app /app

# User configuration
USER 1000:1000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD python -c "import grpc; import sys; sys.exit(0)"

# Default command (can be overridden in docker-compose)
CMD ["python", "-m", "src.${SERVICE_NAME}.main"]
