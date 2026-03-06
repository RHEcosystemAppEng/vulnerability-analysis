# Multi-stage build for smaller image
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app

# Copy dependency files
COPY pyproject.toml .python-version ./

# Install dependencies
RUN uv sync --frozen --no-dev --no-install-project

# Copy application code
COPY evaluation/ ./evaluation/
COPY scripts/ ./scripts/

# Install the project
RUN uv sync --frozen --no-dev

# Final stage
FROM python:3.12-slim

WORKDIR /app

# Copy from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/evaluation /app/evaluation
COPY --from=builder /app/scripts /app/scripts

# Set environment
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Create non-root user
RUN useradd -m -u 1000 evaluator && \
    chown -R evaluator:evaluator /app

USER evaluator

# Health check (optional)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command
ENTRYPOINT ["python", "scripts/run_evaluation.py"]
CMD ["--mode", "api", "--stages", "all", "--submit"]
