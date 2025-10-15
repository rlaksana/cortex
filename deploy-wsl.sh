#!/bin/bash

# Cortex Memory MCP - WSL2 Docker Deployment Script
# This script deploys Cortex Memory MCP to Docker running in WSL2

set -e

echo "🚀 Starting Cortex Memory MCP deployment to Docker WSL2..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in WSL
print_status "Checking WSL environment..."
if ! grep -q Microsoft /proc/version; then
    print_error "This script is designed to run in WSL environment"
    exit 1
fi

print_success "WSL environment detected"

# Check if Docker is available in WSL
print_status "Checking Docker availability in WSL..."
if ! command -v docker &> /dev/null; then
    print_warning "Docker not found in WSL. Attempting to install Docker..."

    # Update package index
    sudo apt-get update

    # Install packages to allow apt to use a repository over HTTPS
    sudo apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release

    # Add Docker's official GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

    # Set up the repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker Engine
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

    # Start Docker service
    sudo systemctl start docker
    sudo systemctl enable docker

    # Add current user to docker group
    sudo usermod -aG docker $USER

    print_success "Docker installed in WSL"
    print_warning "You may need to log out and log back in for docker group changes to take effect"
else
    print_success "Docker is already available in WSL"
fi

# Check if Docker is running
print_status "Checking if Docker daemon is running..."
if ! docker info &> /dev/null; then
    print_warning "Docker daemon is not running. Starting it..."
    sudo systemctl start docker
    sleep 3

    if ! docker info &> /dev/null; then
        print_error "Failed to start Docker daemon"
        exit 1
    fi
fi

print_success "Docker daemon is running"

# Navigate to project directory
PROJECT_DIR="/mnt/d/WORKSPACE/tools-node/mcp-cortex"
print_status "Navigating to project directory: $PROJECT_DIR"
cd "$PROJECT_DIR"

# Create environment file if it doesn't exist
if [ ! -f .env ]; then
    print_status "Creating .env file from template..."
    cp .env.example .env
    print_warning "Please review and update .env file with your configuration"
fi

# Build and deploy with Docker Compose
print_status "Building and deploying Cortex Memory MCP..."
docker-compose down 2>/dev/null || true  # Stop existing containers if any
docker-compose build --no-cache
docker-compose up -d

# Wait for services to be ready
print_status "Waiting for services to be ready..."
sleep 10

# Check service status
print_status "Checking service status..."
docker-compose ps

# Check database health
print_status "Checking PostgreSQL database health..."
DB_HEALTH=$(docker-compose exec -T postgres pg_isready -U cortex -d cortex_prod 2>/dev/null || echo "failed")
if [[ "$DB_HEALTH" == *"accepting connections"* ]]; then
    print_success "PostgreSQL database is healthy"
else
    print_warning "PostgreSQL database may still be initializing..."
fi

# Check server logs
print_status "Checking Cortex server logs..."
docker-compose logs server --tail=20

# Display deployment information
print_success "🎉 Cortex Memory MCP deployment completed!"
echo ""
echo "=== Deployment Information ==="
echo "📁 Project Directory: $PROJECT_DIR"
echo "🐳 PostgreSQL Container: cortex-postgres (port 5433)"
echo "🔧 Cortex Server Container: cortex-server"
echo "🌐 Database Connection: postgresql://cortex:password@localhost:5433/cortex_prod"
echo ""
echo "=== Useful Commands ==="
echo "View logs:           docker-compose logs -f"
echo "Stop services:       docker-compose down"
echo "Restart services:    docker-compose restart"
echo "Access database:     docker-compose exec postgres psql -U cortex -d cortex_prod"
echo "Check status:        docker-compose ps"
echo ""
echo "=== Next Steps ==="
echo "1. Update .env file with your desired configuration"
echo "2. Test the MCP server connection"
echo "3. Configure your MCP client to connect to the server"
echo ""

# Store deployment information in Cortex Memory
print_status "Recording deployment information..."
curl -X POST http://localhost:3000/memory/store \
    -H "Content-Type: application/json" \
    -d '{
        "items": [{
            "kind": "change",
            "scope": {"project": "mcp-cortex", "branch": "001-create-specs-000"},
            "data": {
                "title": "WSL2 Docker Deployment",
                "body_md": "## Cortex Memory MCP WSL2 Deployment\n\n**Date:** '$(date)'\n**Environment:** WSL2 Ubuntu\n**Docker Version:** '$(docker --version)'\n**Services:** PostgreSQL + Cortex Server\n\n### Configuration\n- PostgreSQL Port: 5433\n- Database: cortex_prod\n- User: cortex\n- Status: Running\n\n### Next Steps\n1. Configure MCP client connection\n2. Test memory operations\n3. Monitor logs for any issues"
            }
        }]
    }' 2>/dev/null || print_warning "Could not record deployment to memory (server may still be starting)"

print_success "Deployment process completed! 🚀"