# Simple Python-only build for faster testing
FROM python:3.9-slim-bookworm
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir flask psycopg2-binary flask-limiter

EXPOSE 8001

CMD ["python", "main_test.py"]
