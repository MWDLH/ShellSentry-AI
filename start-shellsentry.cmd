@echo off
setlocal
cd /d "%~dp0"
title ShellSentry-AI

set "VENV_PYTHON=%CD%\.venv\Scripts\python.exe"

if not exist "%VENV_PYTHON%" (
    echo [ShellSentry] First launch: creating a private Python environment...
    where py >nul 2>nul
    if not errorlevel 1 (
        py -3 -m venv .venv
    ) else (
        where python >nul 2>nul
        if errorlevel 1 goto :no_python
        python -m venv .venv
    )
    if errorlevel 1 goto :setup_failed
)

"%VENV_PYTHON%" -c "import shellsentry, fastapi, uvicorn, openai, multipart" >nul 2>nul
if errorlevel 1 (
    echo [ShellSentry] Installing local runtime dependencies...
    "%VENV_PYTHON%" -m pip install --disable-pip-version-check -e .
    if errorlevel 1 goto :setup_failed
)

echo [ShellSentry] Starting. The browser will open automatically.
echo [ShellSentry] Close this window or press Ctrl+C to stop the platform.
"%VENV_PYTHON%" -m shellsentry serve --port 8765
if errorlevel 1 goto :run_failed
exit /b 0

:no_python
echo [ShellSentry] Python 3.10 or newer was not found.
echo Install Python from https://www.python.org/downloads/ and enable "Add Python to PATH".
pause
exit /b 1

:setup_failed
echo [ShellSentry] Setup failed. Check the network connection and the error above.
pause
exit /b 1

:run_failed
echo [ShellSentry] The platform stopped because of an error.
pause
exit /b 1
