# ==============================================================================
# СЛОЙ 1: Сборка зависимостей (Builder)
# ==============================================================================
FROM python:3.11-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip wheel --no-cache-dir --wheel-dir /app/wheels -r requirements.txt


# ==============================================================================
# СЛОЙ 2: Финальный минимальный образ (Production)
# ==============================================================================
FROM python:3.11-slim AS production

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 appgroup && \
    useradd -u 10000 -g appgroup -m -s /bin/false appuser

COPY --from=builder /app/wheels /tmp/wheels
COPY requirements.txt .

RUN pip install --no-cache-dir --no-index --find-links=/tmp/wheels -r requirements.txt && \
    rm -rf /tmp/wheels

COPY . .

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]