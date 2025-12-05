# -----------------------------
# Stage 1: Builder
# -----------------------------
FROM python:3.11-slim AS builder

WORKDIR /app

# Copy dependency file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --prefix=/install -r requirements.txt

# -----------------------------
# Stage 2: Runtime
# -----------------------------
FROM python:3.11-slim AS runtime

# Set timezone to UTC
ENV TZ=UTC

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y cron tzdata && \
    ln -sf /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . /app

# Setup cron job
# Ensure your cron job file is called "cronfile" in the repo
RUN chmod 0644 /app/cronfile && \
    crontab /app/cronfile

# Create volume mount points
RUN mkdir -p /data /cron && chmod 755 /data /cron

# Expose port 8080
EXPOSE 8080

# Start cron and FastAPI server
CMD cron && uvicorn api:app --host 0.0.0.0 --port 8080
