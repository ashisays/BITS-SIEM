# BITS-SIEM Processing Service Dockerfile
# Multi-stage build for Python application with security optimizations

FROM python:3.11-slim as builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Create non-root user for security
RUN groupadd -r siem && useradd -r -g siem siem

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Python packages from builder stage
COPY --from=builder /root/.local /home/siem/.local

# Copy application code
COPY --chown=siem:siem . .

# Ensure Python can find packages
ENV PATH=/home/siem/.local/bin:$PATH
ENV PYTHONPATH=/app

# Create necessary directories
RUN mkdir -p /app/logs /app/data \
    && chown -R siem:siem /app

# Switch to non-root user
USER siem

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose metrics port
EXPOSE 8082

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8082/health || exit 1

# Start command
CMD ["python", "main.py"] 