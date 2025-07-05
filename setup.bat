@echo off
echo Setting up HereFishyFishy Domain Trust Scoring Tool...
echo ======================================================

REM Create virtual environment if it doesn't exist
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

REM Activate virtual environment and install dependencies
echo Installing dependencies...
.venv\Scripts\activate.bat && .venv\Scripts\pip.exe install -r requirements.txt

echo.
echo Setup complete! You can now run:
echo   .venv\Scripts\python.exe prototype.py ^<domain^>
echo.
echo Or run the test script:
echo   test.bat
echo.
pause
