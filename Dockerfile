FROM python:3.12-slim

WORKDIR /app

# Install dependencies first so they're cached independently of source changes.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY run_books/ ./run_books/

RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app
USER appuser

# Default entrypoint: the MCP server (the project's primary, supported way to
# run it). Other consumers (the Investigation API, the AI Controller) override
# this via docker-compose.yml's `command:`.
CMD ["python", "-m", "src.mcp.mcp_server"]
