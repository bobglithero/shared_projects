#!/bin/bash
# build.sh - Build the MCP Security Demonstration Environment

set -e

echo "🚀 Building MCP Security Demonstration Environment"
echo "================================================="

# Configuration
IMAGE_NAME="mcp-security-demo"
VERSION="1.0.0"
DEMO_TAG="educational-mcp-vulnerabilities"

# Create build context
echo "📁 Preparing build context..."
mkdir -p demo-setup/{mcp-servers,demo-data,configs,scripts}

# Copy all demo files to build context
echo "📋 Copying demonstration files..."

# Create pyproject.toml for MCP servers
cat > demo-setup/mcp-servers/pyproject.toml << 'EOF'
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "mcp-security-demo-servers"
version = "1.0.0"
description = "Educational MCP servers demonstrating security vulnerabilities"
authors = [{name = "Security Education Project"}]
dependencies = [
    "httpx>=0.24.0",
    "fastapi>=0.100.0",
    "uvicorn>=0.20.0",
    "pydantic>=2.0.0"
]

[project.scripts]
mock-intelligence-mcp = "mock_intelligence_mcp:main"
enhanced-master-mcp = "enhanced_master_mcp:main"

[tool.setuptools.packages.find]
where = ["."]
EOF

# Create the main MCP server files (missing from original)
# Copy mock_intelligence_mcp.py content
cp mock_intelligence_mcp.py demo-setup/mcp-servers/ 2>/dev/null || {
    echo "Error: mock_intelligence_mcp.py not found in current directory"
    echo "Please ensure all Python files are in the build directory"
    exit 1
}

# Copy enhanced_master_mcp.py content  
cp enhanced_master_mcp.py demo-setup/mcp-servers/ 2>/dev/null || {
    echo "Error: enhanced_master_mcp.py not found in current directory"
    echo "Please ensure all Python files are in the build directory"
    exit 1
}

# Create poisoned document generator
cp create_poisoned_intel_doc.py demo-setup/demo-data/ 2>/dev/null || {
    echo "Error: create_poisoned_intel_doc.py not found in current directory"
    exit 1
}

# Create monitoring script
cp monitor_attack.py demo-setup/scripts/ 2>/dev/null || {
    echo "Error: monitor_attack.py not found in current directory"
    exit 1
}

# Create capture server script  
cp capture_server.py demo-setup/scripts/ 2>/dev/null || {
    echo "Error: capture_server.py not found in current directory"
    exit 1
}

# Build the Docker image
echo "🐳 Building Docker image..."
docker build -t ${IMAGE_NAME}:${VERSION} .

# Tag with descriptive information
echo "🏷️  Tagging image..."
docker tag ${IMAGE_NAME}:${VERSION} ${IMAGE_NAME}:latest
docker tag ${IMAGE_NAME}:${VERSION} ${IMAGE_NAME}:${DEMO_TAG}
docker tag ${IMAGE_NAME}:${VERSION} ${IMAGE_NAME}:government-intelligence-demo

# Create additional tags with metadata
BUILD_DATE=$(date -u +'%Y-%m-%d_%H-%M-%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

docker tag ${IMAGE_NAME}:${VERSION} ${IMAGE_NAME}:build-${BUILD_DATE}
docker tag ${IMAGE_NAME}:${VERSION} ${IMAGE_NAME}:commit-${GIT_COMMIT}

echo "✅ Build complete!"
echo ""
echo "📦 Created Docker images:"
echo "  - ${IMAGE_NAME}:${VERSION}"
echo "  - ${IMAGE_NAME}:latest"
echo "  - ${IMAGE_NAME}:${DEMO_TAG}"
echo "  - ${IMAGE_NAME}:government-intelligence-demo"
echo "  - ${IMAGE_NAME}:build-${BUILD_DATE}"
echo "  - ${IMAGE_NAME}:commit-${GIT_COMMIT}"
echo ""
echo "🎯 Ready for educational security demonstrations"
echo "⚠️  FOR AUTHORIZED EDUCATIONAL USE ONLY"
