# Use Python 3.10 as the base image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV ENVIRONMENT=production

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create directories for PKD components
RUN mkdir -p /data/pkd/masterlist /data/pkd/dsclist /data/pkd/crl

# Copy requirements file
COPY src/pkd_service/requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir uv && \
    uv pip install --system --no-cache -r requirements.txt && \
    uv pip install --system grpcio

# Copy application code
COPY src/pkd_service/app /app/app

# Create a non-root user
RUN adduser --disabled-password --gecos "" appuser
RUN chown -R appuser:appuser /app /data
USER appuser

# Expose port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]