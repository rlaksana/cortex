@echo off
echo Updating project paths for new location...

REM Get current directory
set CURRENT_DIR=%CD%

REM Update simple MCP config
echo Updating config/simple-mcp-config.json...
powershell -Command "(Get-Content 'config\simple-mcp-config.json') -replace 'D:\\\\WORKSPACE\\\\tools-node\\\\mcp-cortex', '%CURRENT_DIR%' | Set-Content 'config\simple-mcp-config.json'"

REM Update development policy examples
echo Updating DEVELOPMENT-POLICY.md examples...
powershell -Command "(Get-Content 'DEVELOPMENT-POLICY.md') -replace 'D:\\\\WORKSPACE\\\\tools-node\\\\mcp-cortex', '%CURRENT_DIR%' | Set-Content 'DEVELOPMENT-POLICY.md'"

REM Update AI assistant guidelines
echo Updating .ai-assistant-guidelines.md...
powershell -Command "(Get-Content '.ai-assistant-guidelines.md') -replace 'D:\\\\WORKSPACE\\\\tools-node\\\\mcp-cortex', '%CURRENT_DIR%' | Set-Content '.ai-assistant-guidelines.md'"

echo.
echo ✅ All paths updated to: %CURRENT_DIR%
echo.
echo Your MCP config now points to:
echo %CURRENT_DIR%\dist\index.js
echo.
pause