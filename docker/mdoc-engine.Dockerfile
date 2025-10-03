# Dockerfile for mdoc-engine service
FROM marty-base:latest

# Copy service-specific code
COPY src/mdoc_engine ./src/mdoc_engine

# Set service-specific environment variables
ENV SERVICE_NAME=mdoc-engine
ENV GRPC_PORT=8086

# Expose service-specific port
EXPOSE 8086

# Command to run when container starts
CMD ["python", "-m", "src.apps.mdoc_engine"]
