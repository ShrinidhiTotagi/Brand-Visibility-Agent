FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Env defaults (override at runtime)
ENV AGENT_PORT=8000
ENV AGENT_HOST=0.0.0.0
ENV AGENT_DB=sqlite
ENV AUTH_DEFAULT_USER=admin
ENV AUTH_DEFAULT_PASS=changeme123
ENV CORS_ALLOWED_ORIGINS=*
ENV RATE_LIMIT_PER_MINUTE=60

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

CMD ["python", "agent.py"]
