# Hardened PKD Service Dockerfile
FROM marty-base:latest

# Security: Start as non-root user (inherited from base image)
USER 1000:1000

# Copy service-specific code with proper ownership
COPY --chown=1000:1000 src/pkd_service ./src/pkd_service

# Set environment variables
ENV ENVIRONMENT=production
ENV GRPC_PORT=9088
ENV HTTP_PORT=8088

# Create directories for PKD components with proper permissions
USER root
RUN mkdir -p /data/pkd/masterlist /data/pkd/dsclist /data/pkd/crl && \
    chown -R 1000:1000 /data && \
    chmod 755 /data/pkd /data/pkd/masterlist /data/pkd/dsclist /data/pkd/crl

# Switch back to non-root user
USER 1000:1000

# Security: Set read-only filesystem for application files
RUN find /app/src/pkd_service -type f -exec chmod 444 {} \; && \
    find /app/src/pkd_service -type d -exec chmod 555 {} \;

# Security labels
LABEL security.non-root="true"
LABEL security.service="pkd-service"
LABEL security.version="1.0.0"

# Expose ports (metadata only)
EXPOSE 8088 9088

# Enhanced health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8088/health || exit 1

# Security: Run with minimal privileges
# In docker-compose or k8s, add: --cap-drop=ALL --read-only --tmpfs /tmp
# Example runtime: docker run --cap-drop=ALL --read-only --tmpfs /tmp

# Command to run the application
CMD ["uvicorn", "src.pkd_service.main:app", "--host", "0.0.0.0", "--port", "8088"]