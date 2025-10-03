# Trust Anchor Service Dockerfile
FROM marty-base:latest

# Copy service-specific code
COPY src/trust_anchor ./src/trust_anchor

# Health check endpoint (optional, requires service to expose one)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose default port
EXPOSE 8080

# Default port for gRPC service
EXPOSE 9090

# Run the trust anchor service
CMD ["python", "-m", "trust_anchor.main"]
