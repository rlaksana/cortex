@echo off
echo === EMFILE Stress Testing ===

REM Set up EMFILE prevention environment
set EMFILE_HANDLES_LIMIT=131072
set UV_THREADPOOL_SIZE=16
set TEST_TIMEOUT=30000
set TEST_WORKERS=4
set NODE_OPTIONS=--max-old-space-size=4096 --max-semi-space-size=256 --optimize-for-size --gc-interval=100

echo.
echo 1. Running concurrent test workers...
start "Test Worker 1" cmd /c "npm run test:unit"
start "Test Worker 2" cmd /c "npm run test:integration"
timeout /t 5

echo.
echo 2. Running coverage tests with memory profiling...
npm run test:coverage:memory 2>nul || echo Memory test not available, running standard coverage...
npm run test:coverage

echo.
echo 3. Running performance stress tests...
npm run test:performance:stress 2>nul || echo Stress test not available, running performance tests...
npm run test:performance

echo.
echo 4. Testing handle cleanup under load...
for /L %%i in (1,1,3) do (
    echo Iteration %%i
    npm run test:unit 2>nul || echo Unit test failed on iteration %%i
    timeout /t 2
)

echo.
echo 5. Testing multiple coverage reports concurrently...
start "Coverage 1" cmd /c "npm run test:coverage:unit"
start "Coverage 2" cmd /c "npm run test:coverage:integration"
timeout /t 10

echo.
echo === Stress Testing Complete ===
echo Check for any EMFILE errors in the output above