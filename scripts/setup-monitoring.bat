@echo off
REM Cortex MCP Monitoring Setup Script for Windows
REM This script sets up the complete monitoring stack for Cortex Memory MCP

setlocal enabledelayedexpansion

REM Configuration
set "MONITORING_PORT=9090"
set "GRAFANA_PORT=3000"
set "PROMETHEUS_PORT=9091"
set "ALERTMANAGER_PORT=9093"
set "NODE_EXPORTER_PORT=9100"

echo.
echo ��� Cortex MCP Monitoring Setup
echo ===============================
echo.

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

REM Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not running. Please start Docker Desktop first.
    pause
    exit /b 1
)

echo [INFO] Docker is installed and running.

REM Create necessary directories
echo [INFO] Creating necessary directories...
if not exist "prometheus\data" mkdir prometheus\data
if not exist "grafana\data" mkdir grafana\data
if not exist "grafana\provisioning\datasources" mkdir grafana\provisioning\datasources
if not exist "grafana\provisioning\dashboards" mkdir grafana\provisioning\dashboards
if not exist "alertmanager\data" mkdir alertmanager\data

echo [SUCCESS] Directories created successfully.

REM Start monitoring stack
echo [INFO] Starting monitoring stack...
docker-compose -f docker\monitoring-stack.yml up -d

if %errorlevel% neq 0 (
    echo [ERROR] Failed to start monitoring stack.
    pause
    exit /b 1
)

echo [SUCCESS] Monitoring stack started successfully.

REM Wait for services to be ready
echo [INFO] Waiting for services to be ready...

set /a "max_attempts=30"
set /a "attempt=1"

:wait_prometheus
curl -s http://localhost:%PROMETHEUS_PORT%/-/healthy >nul 2>&1
if %errorlevel% equ 0 (
    echo [SUCCESS] Prometheus is ready.
    goto :wait_grafana
)

if %attempt% geq %max_attempts% (
    echo [ERROR] Prometheus failed to start within expected time.
    goto :end
)

echo [INFO] Waiting for Prometheus... (attempt %attempt%/%max_attempts%)
timeout /t 10 /nobreak >nul
set /a "attempt+=1"
goto :wait_prometheus

:wait_grafana
set /a "attempt=1"

:wait_grafana_loop
curl -s http://localhost:%GRAFANA_PORT%/api/health >nul 2>&1
if %errorlevel% equ 0 (
    echo [SUCCESS] Grafana is ready.
    goto :verify_setup
)

if %attempt% geq %max_attempts% (
    echo [ERROR] Grafana failed to start within expected time.
    goto :end
)

echo [INFO] Waiting for Grafana... (attempt %attempt%/%max_attempts%)
timeout /t 10 /nobreak >nul
set /a "attempt+=1"
goto :wait_grafana_loop

:verify_setup
echo [INFO] Verifying monitoring setup...

REM Check if Cortex MCP metrics are available
curl -s http://localhost:%MONITORING_PORT%/metrics >nul 2>&1
if %errorlevel% equ 0 (
    echo [SUCCESS] Cortex MCP metrics endpoint is accessible.
) else (
    echo [WARNING] Cortex MCP metrics endpoint is not accessible. Make sure the Cortex MCP server is running with monitoring enabled.
)

REM Check Prometheus targets
curl -s "http://localhost:%PROMETHEUS_PORT%/api/v1/targets" | findstr "cortex-mcp" >nul 2>&1
if %errorlevel% equ 0 (
    echo [SUCCESS] Prometheus is configured to scrape Cortex MCP metrics.
) else (
    echo [WARNING] Prometheus may not be properly configured to scrape Cortex MCP metrics.
)

REM Check Grafana datasource
curl -s "http://localhost:%GRAFANA_PORT%/api/datasources" | findstr "Prometheus" >nul 2>&1
if %errorlevel% equ 0 (
    echo [SUCCESS] Grafana Prometheus datasource is configured.
) else (
    echo [WARNING] Grafana Prometheus datasource may not be properly configured.
)

:show_info
echo.
echo [SUCCESS] Monitoring setup complete!
echo.
echo Access URLs:
echo   • Grafana Dashboard:     http://localhost:%GRAFANA_PORT% (admin/admin123)
echo   • Prometheus:           http://localhost:%PROMETHEUS_PORT%
echo   • Alertmanager:         http://localhost:%ALERTMANAGER_PORT%
echo   • Cortex MCP Metrics:   http://localhost:%MONITORING_PORT%/metrics
echo.
echo Quick Commands:
echo   • View logs:            docker-compose -f docker\monitoring-stack.yml logs -f
echo   • Stop monitoring:      docker-compose -f docker\monitoring-stack.yml down
echo   • Restart services:     docker-compose -f docker\monitoring-stack.yml restart
echo.
echo Next Steps:
echo   1. Open Grafana and explore the pre-configured dashboard
echo   2. Configure alert channels in Alertmanager
echo   3. Customize alert thresholds in prometheus\alerts\cortex.rules.yaml
echo   4. Review the monitoring documentation: docs\MONITORING-SETUP.md
echo.

goto :end

:stop
echo [INFO] Stopping monitoring stack...
docker-compose -f docker\monitoring-stack.yml down
if %errorlevel% equ 0 (
    echo [SUCCESS] Monitoring stack stopped.
) else (
    echo [ERROR] Failed to stop monitoring stack.
)
goto :end

:restart
echo [INFO] Restarting monitoring stack...
docker-compose -f docker\monitoring-stack.yml restart
if %errorlevel% equ 0 (
    echo [SUCCESS] Monitoring stack restarted.
) else (
    echo [ERROR] Failed to restart monitoring stack.
)
goto :end

:status
echo [INFO] Monitoring stack status:
docker-compose -f docker\monitoring-stack.yml ps
goto :end

:help
echo Cortex MCP Monitoring Setup Script for Windows
echo.
echo Usage: %~nx0 [command]
echo.
echo Commands:
echo   (no args)  Set up monitoring stack
echo   stop       Stop monitoring stack
echo   restart    Restart monitoring stack
echo   status     Show status of monitoring services
echo   help       Show this help message
echo.
echo Environment Variables:
echo   MONITORING_PORT       Port for Cortex MCP monitoring (default: 9090)
echo   GRAFANA_PORT          Grafana port (default: 3000)
echo   PROMETHEUS_PORT       Prometheus port (default: 9091)
echo   ALERTMANAGER_PORT     Alertmanager port (default: 9093)
echo   NODE_EXPORTER_PORT    Node Exporter port (default: 9100)
echo.
goto :end

:end
if "%1"=="" pause