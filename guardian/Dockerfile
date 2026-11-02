FROM python:3.11-slim

WORKDIR /app

# Prevent Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src:/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and tests
COPY . .

# Expose HTTP / WebSocket port
EXPOSE 8000

# Run FastAPI via Uvicorn
CMD ["uvicorn", "src.guardian.main:app", "--host", "0.0.0.0", "--port", "8000"]
