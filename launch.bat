@echo off
setlocal

rem SecureBootLab - one-click launcher
rem Sets up (or reuses) a virtual environment, verifies/installs Python
rem dependencies, starts the FastAPI backend and the dashboard file server,
rem then opens SecureBoot.html (Live Monitor) in the default browser.

cd /d "%~dp0"

echo ============================================
echo  SecureBootLab - Launch
echo ============================================

rem 1. Locate a Python interpreter on PATH
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found on PATH. Install Python 3.11+ and retry.
    pause
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 (
    echo [ERROR] Python 3.11+ is required.
    python --version
    pause
    exit /b 1
)

rem 2. Create the virtual environment if it does not exist yet
if not exist ".venv\Scripts\python.exe" (
    echo [SETUP] Creating virtual environment in .venv ...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
) else (
    echo [SETUP] Reusing existing virtual environment .venv
)

set "VENV_PY=%~dp0.venv\Scripts\python.exe"

rem 3. Verify / install all dependencies from requirements.txt
echo [SETUP] Checking Python dependencies ...
"%VENV_PY%" -m pip install --quiet --upgrade pip
if errorlevel 1 (
    echo [ERROR] Failed to upgrade pip.
    pause
    exit /b 1
)

"%VENV_PY%" -m pip install --quiet -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Dependency installation failed. See output above.
    pause
    exit /b 1
)

echo [SETUP] Dependencies OK.

rem 4. Start the FastAPI backend (port 8000) in its own window
echo [START] Launching FastAPI backend on http://localhost:8000 ...
start "SecureBootLab - API (port 8000)" cmd /k "%VENV_PY%" -m uvicorn api.main:app --reload --port 8000

rem 5. Start the dashboard static file server (port 3000) in its own window
echo [START] Launching dashboard server on http://localhost:3000 ...
start "SecureBootLab - Dashboard (port 3000)" cmd /k "%VENV_PY%" -m http.server 3000 --directory docs

rem 6. Give both servers a moment to come up, then open the live monitor
timeout /t 3 /nobreak >nul

echo [OPEN] Opening SecureBoot.html in default browser ...
start "" "http://localhost:3000/SecureBoot.html"

echo.
echo Backend and dashboard are running in their own windows.
echo Close those windows (or press Ctrl+C in each) to stop the servers.
echo.
pause
