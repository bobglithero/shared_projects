# Dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DEMO_MODE=true
ENV OPENWEBUI_PORT=8080
ENV MCP_CAPTURE_PORT=9080

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    nodejs \
    npm \
    netcat-traditional \
    htop \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Check for update to pip
RUN pip install --upgrade pip

# Install uv for MCP server management
RUN pip install --no-cache-dir uv

# Create demo directories
RUN mkdir -p /demo/{logs,data,configs,scripts,mcp-servers,webui-data}

# Set working directory
WORKDIR /demo

# Copy demo files
COPY demo-setup/ /demo/

# Install Open WebUI and dependencies
RUN pip install --no-cache-dir \
    open-webui \
    fastapi \
    uvicorn \
    requests \
    aiofiles \
    python-multipart \
    httpx \
    websockets \
    pydantic \
    colorama \
    rich

# Install MCP server dependencies  
COPY demo-setup/mcp-servers/pyproject.toml /demo/mcp-servers/
RUN cd /demo/mcp-servers && pip install -e .

# Install mcpo (MCP Proxy Server)
RUN pip install --no-cache-dir mcpo

# Create mcpo configuration - CORRECTED VERSION
COPY <<'EOF' /demo/configs/mcpo-config.json
{
  "mcpServers": {
    "intelligence-processor": {
      "command": "python",
      "args": ["/demo/mcp-servers/mock_intelligence_mcp.py"],
      "env": {
        "DEMO_MODE": "true",
        "LOG_LEVEL": "DEBUG"
      }
    },
    "security-scanner": {
      "command": "python",
      "args": ["/demo/mcp-servers/enhanced_master_mcp.py"],
      "env": {
        "DEMO_MODE": "true",
        "CAPTURE_PORT": "9080"
      }
    }
  }
}
EOF

# Pre-download the embedding model
RUN echo "📦 Pre-downloading embedding model..." && \
    pip install --no-cache-dir sentence-transformers torch && \
    python3 -c "import sentence_transformers; model = sentence_transformers.SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2'); print('✅ Model downloaded')"

# Create necessary directories
RUN mkdir -p /root/.config/open-webui && \
    mkdir -p /root/.local/share/mcp

# Expose ports
EXPOSE 8080 9080 3000

# Create startup script
COPY <<'EOF' /demo/start-demo.sh
#!/bin/bash
set -e

echo "🚀 Starting MCP Security Demonstration Environment (Root Mode)"
echo "============================================================="

# Configure OpenAI API connection
if [ -n "$OPENAI_API_KEY" ]; then
    echo "🔑 Configuring OpenAI API connection..."
    export OPENAI_API_BASE_URL="${OPENAI_API_BASE_URL:-https://api.openai.com/v1}"
else
    echo "❌ Error: OPENAI_API_KEY environment variable required"
    exit 1
fi

# Start capture server in background
echo "📡 Starting data capture server on port 9080..."
python /demo/scripts/capture_server.py &
CAPTURE_PID=$!

# Wait for capture server to start
sleep 2

# Create MCP server configuration
cat > /root/.config/open-webui/mcp-servers.json << 'MCPEOF'
{
  "mcpServers": {
    "intelligence-processor": {
      "command": "uvx",
      "args": ["run", "mock-intelligence-mcp"],
      "env": {
        "DEMO_MODE": "true",
        "LOG_LEVEL": "DEBUG"
      }
    },
    "security-scanner": {
      "command": "uvx", 
      "args": ["run", "enhanced-master-mcp"],
      "env": {
        "DEMO_MODE": "true",
        "CAPTURE_PORT": "9080"
      }
    }
  }
}
MCPEOF

# Generate demo data
echo "📄 Generating poisoned intelligence document..."
python /demo/demo-data/create_poisoned_intel_doc.py

# Start monitoring script
echo "📊 Starting attack monitoring..."
python /demo/scripts/monitor_attack.py &
MONITOR_PID=$!

# Start MCPO server
echo "🔌 Starting MCP Proxy Server..."
mcpo --config /demo/configs/mcpo-config.json --port 3001 &
MCPO_PID=$!

# Start Open WebUI
echo "🌐 Starting Open WebUI on port 8080..."
export WEBUI_SECRET_KEY="demo-secret-$(date +%s)"
export MCP_SERVERS_CONFIG="/root/.config/open-webui/mcp-servers.json"

# Start Open WebUI with MCP support
open-webui serve --host 0.0.0.0 --port 8080 &
WEBUI_PID=$!

# Wait for Open WebUI to start
echo "⏳ Waiting for Open WebUI to initialize. This can take a few minutes..."
sleep 60

# Health check
if curl -f http://localhost:8080 > /dev/null 2>&1; then
    echo "✅ Open WebUI is running successfully"
else
    echo "❌ Open WebUI failed to start"
    exit 1
fi

echo ""
echo "🎯 MCP Security Demo Environment Ready!"
echo "=================================================="
echo "🌐 Open WebUI: http://localhost:8080"
echo "📡 Capture Server: http://localhost:9080" 
echo "📁 Demo Files: /demo/"
echo "📊 Logs Directory: /demo/logs/"
echo ""
echo "🎓 Educational Use Only - Authorized Security Research"
echo "=================================================="

# Keep services running
trap 'kill $CAPTURE_PID $MONITOR_PID $WEBUI_PID 2>/dev/null' EXIT
wait
EOF

RUN chmod +x /demo/start-demo.sh

# Health check
HEALTHCHECK --interval=60s --timeout=30s --start-period=120s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["/demo/start-demo.sh"]