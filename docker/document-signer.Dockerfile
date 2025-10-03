# Dockerfile for document-signer service
FROM marty-base:latest

# Copy service-specific code
COPY src/document_signer ./src/document_signer

# Set service-specific environment variables
ENV SERVICE_NAME=document-signer
ENV GRPC_PORT=9082

# Expose service-specific port
EXPOSE 9082

# Command to run when container starts
CMD ["python", "-m", "src.apps.document_signer"]
