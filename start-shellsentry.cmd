@echo off
setlocal
cd /d "%~dp0"
title ShellSentry-AI

set "VENV_PYTHON=%CD%\.venv\Scripts\python.exe"

rem 选一个 3.10+ 的解释器：py -3 可能指向机器上更旧的版本。
set "BASE_PY="
for %%V in (3.14 3.13 3.12 3.11 3.10) do (
    if not defined BASE_PY (
        py -%%V -c "import sys" >nul 2>nul && set "BASE_PY=py -%%V"
    )
)
if defined BASE_PY goto :have_python
python -c "import sys;assert sys.hexversion>=0x030A0000" >nul 2>nul && set "BASE_PY=python"
if not defined BASE_PY goto :no_python

:have_python
rem 环境不存在，或不是 3.10+，则（重）建。
if not exist "%VENV_PYTHON%" goto :create_venv
"%VENV_PYTHON%" -c "import sys;assert sys.hexversion>=0x030A0000" >nul 2>nul
if not errorlevel 1 goto :venv_ready
echo [ShellSentry] The existing environment uses Python 3.9 or older; rebuilding it...
rmdir /s /q ".venv"

:create_venv
echo [ShellSentry] First launch: creating a private Python environment...
%BASE_PY% -m venv .venv
if errorlevel 1 goto :setup_failed

:venv_ready
"%VENV_PYTHON%" -c "import shellsentry, fastapi, uvicorn, openai, multipart" >nul 2>nul
if not errorlevel 1 goto :launch

echo [ShellSentry] Installing local runtime dependencies...
rem 先升级 pip。venv 自带的 pip 可能早于 21.3，而 editable 安装
rem （PEP 660）是 21.3 才支持的，否则会报 setup.py not found。
"%VENV_PYTHON%" -m pip install --disable-pip-version-check --upgrade pip setuptools wheel
if errorlevel 1 goto :setup_failed
"%VENV_PYTHON%" -m pip install --disable-pip-version-check -e .
if errorlevel 1 goto :setup_failed

:launch
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
