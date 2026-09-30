# TRISHUL gateway + demo tool servers + console UI (static, served by the gateway at /console).
# Models (Ollama, mlx-whisper, DF_Arena) are NOT in the image: they run natively on the Mac.
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY trishul ./trishul
COPY policies ./policies
COPY bench ./bench
COPY ["Landing page and dashboard implementation", "./Landing page and dashboard implementation"]
# editable install keeps trishul/ at /app so the gateway finds the console directory
RUN uv sync --frozen --no-dev
RUN useradd --system --create-home trishul && mkdir /data && chown trishul /data
USER trishul
ENV TRISHUL_DB=/data/trishul.db PATH="/app/.venv/bin:$PATH"
VOLUME /data
EXPOSE 8787 8788
CMD ["trishul", "start", "--db", "/data/trishul.db", "--host", "0.0.0.0", "--port", "8787", "--mcp-port", "8788"]
