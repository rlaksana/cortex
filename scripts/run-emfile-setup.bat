@echo off
REM =============================================================================
REM EMFILE SETUP BATCH FILE
REM =============================================================================
REM This batch file provides easy execution of EMFILE prevention scripts
REM =============================================================================

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..

echo ==============================================================================
echo EMFILE PREVENTION SETUP - Windows Script Suite
echo ==============================================================================
echo.
echo This script will help you configure Windows to prevent EMFILE errors.
echo Please choose from the following options:
echo.

:menu
echo 1. Complete EMFILE Setup (Recommended for first-time setup)
echo 2. Increase System Handle Limits Only
echo 3. Setup Test Environment Only
echo 4. Validate Current Configuration
echo 5. Validate with Performance Benchmarks
echo 6. Fix Common Issues
echo 7. View Help Documentation
echo 0. Exit
echo.
set /p choice="Enter your choice (0-7): "

if "%choice%"=="1" goto complete_setup
if "%choice%"=="2" goto handle_limits
if "%choice%"=="3" goto test_env
if "%choice%"=="4" goto validate_basic
if "%choice%"=="5" goto validate_benchmark
if "%choice%"=="6" goto fix_issues
if "%choice%"=="7" goto show_help
if "%choice%"=="0" goto exit
echo Invalid choice. Please try again.
echo.
goto menu

:complete_setup
echo.
echo ==============================================================================
echo COMPLETE EMFILE SETUP
echo ==============================================================================
echo.
echo This will run all EMFILE prevention scripts:
echo 1. Increase system handle limits (requires Administrator)
echo 2. Setup test environment
echo 3. Validate configuration
echo.
set /p confirm="Do you want to continue? (y/N): "
if /i not "%confirm%"=="y" goto menu

echo.
echo Step 1: Increasing system handle limits...
powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%increase-handles.ps1"
if errorlevel 1 (
    echo.
    echo ERROR: Handle limit setup failed. Please run as Administrator.
    pause
    goto menu
)

echo.
echo Step 2: Setting up test environment...
powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%setup-test-environment.ps1" -ProjectRoot "%PROJECT_ROOT%"
if errorlevel 1 (
    echo.
    echo ERROR: Test environment setup failed.
    pause
    goto menu
)

echo.
echo Step 3: Validating configuration...
powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%validate-emfile-fixes.ps1" -ProjectRoot "%PROJECT_ROOT%"

echo.
echo ==============================================================================
echo SETUP COMPLETE
echo ==============================================================================
echo.
echo Your system has been configured for EMFILE prevention.
echo Please restart PowerShell and your development environment to apply changes.
echo.
pause
goto menu

:handle_limits
echo.
echo ==============================================================================
echo INCREASE SYSTEM HANDLE LIMITS
echo ==============================================================================
echo.
echo This will increase Windows system handle limits.
echo Requires Administrator privileges.
echo.
set /p confirm="Do you want to continue? (y/N): "
if /i not "%confirm%"=="y" goto menu

powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%increase-handles.ps1"
pause
goto menu

:test_env
echo.
echo ==============================================================================
echo SETUP TEST ENVIRONMENT
echo ==============================================================================
echo.
echo This will configure the test environment with EMFILE prevention settings.
echo.
set /p confirm="Do you want to continue? (y/N): "
if /i not "%confirm%"=="y" goto menu

powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%setup-test-environment.ps1" -ProjectRoot "%PROJECT_ROOT%"
pause
goto menu

:validate_basic
echo.
echo ==============================================================================
echo VALIDATE CONFIGURATION
echo ==============================================================================
echo.
echo This will validate the current EMFILE prevention configuration.
echo.
powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%validate-emfile-fixes.ps1" -ProjectRoot "%PROJECT_ROOT%"
pause
goto menu

:validate_benchmark
echo.
echo ==============================================================================
echo VALIDATE WITH PERFORMANCE BENCHMARKS
echo ==============================================================================
echo.
echo This will run validation with performance benchmarks.
echo This may take a few minutes to complete.
echo.
set /p confirm="Do you want to continue? (y/N): "
if /i not "%confirm%"=="y" goto menu

powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%validate-emfile-fixes.ps1" -ProjectRoot "%PROJECT_ROOT%" -Detailed -Benchmark
pause
goto menu

:fix_issues
echo.
echo ==============================================================================
echo FIX COMMON ISSUES
echo ==============================================================================
echo.
echo This will attempt to automatically fix common EMFILE configuration issues.
echo.
set /p confirm="Do you want to continue? (y/N): "
if /i not "%confirm%"=="y" goto menu

powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%validate-emfile-fixes.ps1" -ProjectRoot "%PROJECT_ROOT%" -FixIssues -Detailed
pause
goto menu

:show_help
echo.
echo ==============================================================================
echo EMFILE PREVENTION - HELP
echo ==============================================================================
echo.
echo Available Scripts:
echo.
echo increase-handles.ps1
echo   - Increases Windows system handle limits
echo   - Requires Administrator privileges
echo   - Creates registry backups
echo   - Usage: powershell -ExecutionPolicy Bypass -File increase-handles.ps1 [-WhatIf]
echo.
echo setup-test-environment.ps1
echo   - Configures test environment variables
echo   - Sets up PowerShell profiles
echo   - Updates .env.test file
echo   - Usage: powershell -ExecutionPolicy Bypass -File setup-test-environment.ps1 [-Force]
echo.
echo validate-emfile-fixes.ps1
echo   - Validates EMFILE prevention configuration
echo   - Analyzes system handle usage
echo   - Runs performance benchmarks
echo   - Usage: powershell -ExecutionPolicy Bypass -File validate-emfile-fixes.ps1 [-Detailed] [-Benchmark]
echo.
echo Common Issues:
echo.
echo EMFILE Errors:
echo   - Run increase-handles.ps1 as Administrator
echo   - Restart system after registry changes
echo   - Check handle usage with validation script
echo.
echo Environment Variables Not Applied:
echo   - Restart PowerShell terminal
echo   - Run validate-emfile-fixes.ps1 -FixIssues
echo   - Check both user and system variables
echo.
echo Performance Issues:
echo   - Run validation with benchmarks
echo   - Monitor handle usage during development
echo   - Consider reducing test worker count
echo.
echo For detailed documentation, see: README-EMFILE-Fixes.md
echo.
pause
goto menu

:exit
echo.
echo Thank you for using the EMFILE Prevention Script Suite!
echo.
timeout /t 2 /nobreak >nul
exit /b 0

:admin_check
REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo WARNING: This script requires Administrator privileges for full functionality.
    echo Some operations may fail without proper permissions.
    echo.
    set /p continue="Continue anyway? (y/N): "
    if /i not "!continue!"=="y" goto menu
)
goto :eof