@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo  CyberShield AI - Defensive Security MVP
echo ==========================================
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher was not found. Install Python 3.11+ and enable "Add Python to PATH".
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating local Python environment...
  py -3.12 -m venv .venv >nul 2>nul
  if errorlevel 1 py -3 -m venv .venv
  if errorlevel 1 goto error
)
echo Installing/updating requirements...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto error
echo Starting LOCAL DEVELOPMENT mode at http://127.0.0.1:8000
echo IMPORTANT: Do not expose this local-development mode to the public internet.
set CYBERSHIELD_LOCAL_DEV=1
start "" http://127.0.0.1:8000
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
goto end
:error
echo.
echo Setup failed. Read the error above. Do not disable Windows Defender globally.
pause
:end
endlocal
