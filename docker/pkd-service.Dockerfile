# Use marty-base image 
FROM marty-base:latest

# Copy service-specific code
COPY src/pkd_service ./src/pkd_service

# Set environment variables
ENV ENVIRONMENT=production

# Create directories for PKD components
RUN mkdir -p /data/pkd/masterlist /data/pkd/dsclist /data/pkd/crl

# Create a non-root user and set ownership
RUN adduser --disabled-password --gecos "" appuser
RUN chown -R appuser:appuser /app /data
USER appuser

# Expose port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]