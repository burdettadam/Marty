# Dockerfile for dtc-engine service
FROM marty-base:latest

# Copy service-specific code
COPY src/dtc_engine ./src/dtc_engine

# Set service-specific environment variables
ENV SERVICE_NAME=dtc-engine
ENV DATA_DIR=/app/data
ENV GRPC_PORT=8087

# Expose the gRPC port
EXPOSE 8087

# Run the service
CMD ["python", "-u", "/app/src/dtc_engine/src/main.py"]
