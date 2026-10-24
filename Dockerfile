# ==============================================================================
# SwitchRail-8583: ISO 8583:1987 / ISO 20022 Financial Switch & REST Gateway
# ==============================================================================
FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY switchrail ./switchrail
RUN pip install --no-cache-dir -e .

EXPOSE 8583 8584

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8584/health || exit 1

ENTRYPOINT ["switchrail", "serve", "--host", "0.0.0.0", "--port", "8584"]
