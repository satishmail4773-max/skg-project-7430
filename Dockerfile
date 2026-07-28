FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    PYTHONHASHSEED=random PYTHONFAULTHANDLER=1
WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]
CMD ["uvicorn", "specsentinel.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--limit-concurrency", "100", "--timeout-keep-alive", "5", "--timeout-graceful-shutdown", "15"]
