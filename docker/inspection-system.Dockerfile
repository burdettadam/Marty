# Inspection System Service Dockerfile
FROM marty-base:latest

# Copy service-specific code
COPY src/inspection_system ./src/inspection_system

# Health check endpoint (optional, requires service to expose one)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose default port
EXPOSE 8080

# Default port for gRPC service
EXPOSE 9090

# Run the inspection system service
CMD ["python", "-m", "inspection_system.main"]
