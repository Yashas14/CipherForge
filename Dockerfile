FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir build && \
    pip install --no-cache-dir -e ".[all]" || pip install --no-cache-dir -e "."

# Copy source
COPY . .

# Production stage
FROM python:3.12-slim

WORKDIR /app

# Security: run as non-root user
RUN useradd --create-home --shell /bin/bash appuser

# Install runtime dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir cryptography argon2-cffi fastapi pydantic uvicorn \
    typer rich structlog python-multipart

COPY --from=builder /app/src ./src
COPY --from=builder /app/cli.py ./cli.py
COPY --from=builder /app/ui ./ui

# Switch to non-root user
USER appuser

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/v1/health')" || exit 1

# Default: run the API server
CMD ["python", "-m", "uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
