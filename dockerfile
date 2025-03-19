FROM python:3.10-slim

# Update and install necessary packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Create logs directory for attestation
RUN mkdir -p /app/logs

# Copy only the necessary files
COPY requirements.txt ./
COPY server.py ./
COPY eval_dataset.json ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create directory for keys
RUN mkdir -p /app/server-keys

# Expose the port the server runs on
EXPOSE 8000

# Use a proper init system to handle signals
ENTRYPOINT ["python", "-u", "server.py"]

# Copy only the necessary files
COPY requirements.txt ./
COPY server.py ./
COPY eval_dataset.json ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    # Remove pip to prevent further installations
    pip uninstall -y pip && \
    # Remove package manager and build tools
    apt-get update && \
    apt-get remove -y --purge build-essential pkg-config && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

# Remove unnecessary components
RUN rm -rf /usr/local/lib/python*/ensurepip/ && \
    rm -rf /usr/local/lib/python*/lib2to3/ && \
    rm -rf /usr/local/lib/python*/turtledemo/ && \
    rm -rf /usr/local/lib/python*/__pycache__/ && \
    rm -rf /usr/local/lib/python*/site-packages/pip* && \
    rm -rf /usr/local/lib/python*/site-packages/setuptools* && \
    find /usr/local/lib/python*/site-packages -name '*.pyc' -delete

# Create directory for keys
RUN mkdir -p /app/server-keys && chown -R appuser:appuser /app

# Create logs directory for attestation
RUN mkdir -p /app/logs && chown -R appuser:appuser /app/logs

# Switch to non-root user
USER appuser

# Expose the port the server runs on
EXPOSE 8000

# Use a proper init system to handle signals
ENTRYPOINT ["python", "-u", "server.py"]