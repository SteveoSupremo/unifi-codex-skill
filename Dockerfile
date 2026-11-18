FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements-mcp.txt ./
RUN pip install --no-cache-dir -r requirements-mcp.txt
COPY scripts/ ./scripts/
COPY references/ ./references/
COPY tests/ ./tests/
USER 1000:1000
CMD ["python", "scripts/mcp_server.py"]
