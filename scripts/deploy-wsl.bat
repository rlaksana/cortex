@echo off
REM Cortex Memory MCP - WSL2 Docker Deployment Script (Windows)
REM This script deploys Cortex Memory MCP to Docker running in WSL2

echo 🚀 Starting Cortex Memory MCP deployment to Docker WSL2...
echo.

REM Colors for Windows console
set "RED=[91m"
set "GREEN=[92m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "NC=[0m"

REM Function to print status
echo %BLUE%[INFO]%NC% Checking WSL2 availability...

REM Check if WSL is available
wsl --list --quiet >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo %RED%[ERROR]%NC% WSL is not available or not properly installed
    echo Please install WSL2 first: https://aka.ms/wsl2
    pause
    exit /b 1
)

echo %GREEN%[SUCCESS]%NC% WSL2 is available

REM Check if Ubuntu is running
echo %BLUE%[INFO]%NC% Checking WSL Ubuntu distribution...
wsl --list --verbose | findstr "Running" >nul
if %ERRORLEVEL% neq 0 (
    echo %YELLOW%[WARNING]%NC% Ubuntu is not currently running, starting it...
    wsl -d Ubuntu -e echo "Ubuntu started"
)

echo %GREEN%[SUCCESS]%NC% WSL Ubuntu is ready

REM Copy deployment script to WSL and execute
echo %BLUE%[INFO]%NC% Transferring deployment script to WSL...
echo %BLUE%[INFO]%NC% This may take a moment...

REM Create the script in WSL
wsl -d Ubuntu bash -c '
# Create directory for deployment
mkdir -p /tmp/cortex-deployment
cd /tmp/cortex-deployment

# Write the deployment script
cat > deploy-cortex-wsl.sh << '\''EOF'\''
#!/bin/bash

# Cortex Memory MCP - WSL2 Docker Deployment Script
set -e

echo "🚀 Starting Cortex Memory MCP deployment in WSL..."

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Navigate to project directory
PROJECT_DIR="/mnt/d/WORKSPACE/tools-node/mcp-cortex"
cd "$PROJECT_DIR"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_status "Installing Docker in WSL..."

    # Update package index
    sudo apt-get update -qq

    # Install prerequisites
    sudo apt-get install -y -qq \
        ca-certificates \
        curl \
        gnupg \
        lsb-release

    # Add Docker GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker
    sudo apt-get update -qq
    sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin

    # Start and enable Docker
    sudo systemctl start docker
    sudo systemctl enable docker

    # Add user to docker group
    sudo usermod -aG docker $USER

    print_success "Docker installed successfully"
else
    print_success "Docker is already installed"
fi

# Start Docker service if not running
if ! docker info &> /dev/null; then
    print_status "Starting Docker service..."
    sudo systemctl start docker
    sleep 5
fi

# Create .env file if needed
if [ ! -f .env ]; then
    cp .env.example .env
    print_warning "Created .env file - please review configuration"
fi

# Deploy with Docker Compose
print_status "Building and deploying Cortex Memory MCP..."
docker-compose down 2>/dev/null || true
docker-compose build --no-cache
docker-compose up -d

# Wait for services
sleep 10

# Check status
print_status "Checking deployment status..."
docker-compose ps

# Database health check
print_status "Checking database health..."
if docker-compose exec -T postgres pg_isready -U cortex -d cortex_prod &>/dev/null; then
    print_success "Database is healthy"
else
    print_warning "Database may still be initializing..."
fi

# Show logs
print_status "Recent server logs:"
docker-compose logs server --tail=10

echo ""
print_success "🎉 Deployment completed successfully!"
echo "Database available on localhost:5433"
echo "Cortex server is running"
EOF

# Make script executable
chmod +x deploy-cortex-wsl.sh

# Execute the deployment script
echo "Executing deployment script..."
bash deploy-cortex-wsl.sh
'

echo.
echo %GREEN%[SUCCESS]%NC% Deployment process initiated in WSL2!
echo.
echo === Next Steps ===
echo 1. Wait for the deployment to complete (check WSL window)
echo 2. Update .env file if needed
echo 3. Test your MCP client connection
echo 4. Monitor with: docker-compose logs -f
echo.
pause