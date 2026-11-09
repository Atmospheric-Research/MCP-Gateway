FROM python:3.12-slim

# Node is only for "published package" servers run with npx.
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY gateway ./gateway
RUN uv sync --frozen --no-dev

RUN useradd --uid 1000 --create-home gateway && mkdir -p /data && chown gateway:gateway /data
USER gateway
VOLUME /data
EXPOSE 8000

# One worker on purpose: live MCP sessions and their subprocesses are held in process memory.
CMD ["uvicorn", "gateway.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--workers", "1"]
