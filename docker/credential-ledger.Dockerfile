# Dockerfile for credential-ledger service
FROM marty-base:latest

# Copy service-specific code
COPY src/credential_ledger ./src/credential_ledger

# Set service-specific environment variables
ENV SERVICE_NAME=credential-ledger
ENV GRPC_PORT=8089

# Expose service-specific port
EXPOSE 8089

# Command to run when container starts
CMD ["python", "-m", "src.apps.credential_ledger"]