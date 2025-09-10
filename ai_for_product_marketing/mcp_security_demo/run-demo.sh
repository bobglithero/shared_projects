#!/bin/bash
# run-demo.sh - Run the MCP Security Demonstration

set -e

# Source environment variables from .env file if it exists
if [ -f ".env" ]; then
    echo "📋 Loading environment variables from .env file..."
    source .env
else
    echo "⚠️  No .env file found in current directory"
fi

echo "🎯 Starting MCP Security Demonstration Environment"
echo "================================================="

# Check for required OpenAI API key
if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ Error: OpenAI API key required"
    echo "Please set the environment variable:"
    echo "  export OPENAI_API_KEY='your-openai-key'"
    exit 1
fi

# Configuration
IMAGE_NAME="mcp-security-demo"
CONTAINER_NAME="mcp-demo-$(date +%s)"
WEBUI_PORT="3001"
CAPTURE_PORT="9080"
MCPO_PORT="3002"

# Cleanup function
cleanup() {
    echo "🧹 Cleaning up demonstration environment..."
    docker stop ${CONTAINER_NAME} 2>/dev/null || true
    docker rm ${CONTAINER_NAME} 2>/dev/null || true
}

# Set up cleanup on exit
trap cleanup EXIT

# Create volume for persistent logs
docker volume create mcp-demo-logs 2>/dev/null || true

echo "🚀 Starting demonstration container..."
docker run -d \
    --name ${CONTAINER_NAME} \
    -p ${WEBUI_PORT}:8080 \
    -p ${CAPTURE_PORT}:9080 \
    -p ${MCPO_PORT}:3001 \
    -v mcp-demo-logs:/demo/logs \
    -e DEMO_MODE=true \
    -e WEBUI_PORT=8080 \
    -e CAPTURE_PORT=9080 \
    -e OPENAI_API_KEY="${OPENAI_API_KEY}" \
    -e OPENAI_API_BASE_URL="${OPENAI_API_BASE_URL:-https://api.openai.com/v1}" \
    ${IMAGE_NAME}:v1.1

echo "⏳ Initializing services (this may take a few minutes)..."
echo "   📦 Open WebUI is performing database setup"
echo "   🤖 Downloading AI models and dependencies" 
echo "   🔧 Configuring MCP servers"
echo ""
sleep 60

# Check if services are running
echo "🔍 Checking if Open WebUI is ready..."
max_attempts=12
attempt=1
while [ $attempt -le $max_attempts ]; do
    if curl -f -s http://localhost:${WEBUI_PORT}/health > /dev/null 2>&1; then
        echo "✅ Open WebUI is running"
        break
    else
        if [ $attempt -eq $max_attempts ]; then
            echo "❌ Open WebUI failed to start after $max_attempts attempts"
            echo "📋 Container logs:"
            docker logs ${CONTAINER_NAME}
            exit 1
        fi
        echo "⏳ Attempt $attempt/$max_attempts - waiting for Open WebUI..."
        sleep 60
        ((attempt++))
    fi
done

echo "🔍 Checking if capture server is ready..."
if curl -f -s http://localhost:${CAPTURE_PORT}/health > /dev/null 2>&1; then
    echo "✅ Capture server is running"
else
    echo "⚠️  Capture server may still be starting..."
fi

echo ""
echo "🎓 MCP Security Demonstration Ready!"
echo "================================================="
echo "🌐 Open WebUI: http://localhost:${WEBUI_PORT}"
echo "📡 Data Capture Monitor: http://localhost:${CAPTURE_PORT}/health"
echo "📊 Container Logs: docker logs -f ${CONTAINER_NAME}"
echo ""
echo "📋 To run the demonstration:"
echo "1. Open http://localhost:${WEBUI_PORT} in your browser"
echo "2. Configure OpenAI model if not auto-detected"
echo "3. Start a new conversation with the AI"
echo "4. Ask it to analyze the intelligence document"
echo "5. Paste the content from the poisoned document"
echo "6. Watch the attack unfold in the logs"
echo ""
echo "🔍 Monitor attack progress:"
echo "   docker exec -it ${CONTAINER_NAME} python /demo/scripts/monitor_attack.py"
echo ""
echo "📁 Access demo files:"
echo "   docker exec -it ${CONTAINER_NAME} cat /demo/data/poisoned_intelligence_report.txt"
echo ""
echo "⚠️  EDUCATIONAL USE ONLY - AUTHORIZED SECURITY RESEARCH"
echo "================================================="

# Keep script running and show logs
echo "📋 Showing container logs (Press Ctrl+C to stop):"
docker logs -f ${CONTAINER_NAME}