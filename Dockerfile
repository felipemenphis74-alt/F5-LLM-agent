FROM python:3.11-slim

LABEL org.opencontainers.image.title="f5-mcp-agent"
LABEL org.opencontainers.image.description="Read-only MCP agent for F5 BIG-IP monitoring (VS/Pool status, sys connections, tcpdump pattern validation, Excel/Sheets baseline comparison). Never issues config-changing tmsh commands."

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/src/

# Mount points (provide these as volumes at `docker run` time):
#   /app/inventory.yaml   -> your F5 device inventory (see inventory.example.yaml)
#   /app/data             -> Excel baseline files
#   /app/google-creds.json -> optional Google Sheets service account (if used)
ENV PYTHONUNBUFFERED=1 \
    F5_MCP_INVENTORY_PATH=/app/inventory.yaml \
    F5_MCP_DATA_DIR=/app/data

# MCP over stdio: no exposed network port needed.
ENTRYPOINT ["python", "-m", "src.server"]
