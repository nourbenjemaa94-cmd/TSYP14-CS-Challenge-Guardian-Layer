FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY config.example.yaml ./config.example.yaml
COPY mocks ./mocks
COPY run_guardian.py ./run_guardian.py

ENV PYTHONPATH=/app/src
ENV GUARDIAN_CONFIG=/app/config.example.yaml

EXPOSE 8000

# One worker: replay and rate-limit state live in memory.
CMD ["uvicorn", "guardian.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
