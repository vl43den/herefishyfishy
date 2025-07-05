@echo off
REM Simple test script to validate the installation

echo Testing HereFishyFishy Domain Trust Scoring Tool...
echo =================================================

REM Test basic functionality
echo.
echo 1. Testing basic domain analysis (google.com):
.venv\Scripts\python.exe prototype.py google.com

REM Test with whitelist
echo.
echo 2. Testing whitelist functionality:
.venv\Scripts\python.exe prototype.py google.com --whitelist sample_whitelist.txt

REM Test help
echo.
echo 3. Testing help command:
.venv\Scripts\python.exe prototype.py --help

echo.
echo All tests completed!
pause
