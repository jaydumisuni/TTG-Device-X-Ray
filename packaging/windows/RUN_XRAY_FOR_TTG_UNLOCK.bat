@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo.
echo  ============================================
echo   TTG DEVICE X-RAY - Windows Bootstrapper
echo   For TTG UNLOCK V3
echo  ============================================
echo.

set "TARGET_DIR=%CD%"
if exist "..\TTG_UNLOCK_V3" set "TARGET_DIR=%CD%\..\TTG_UNLOCK_V3"
if exist "TTG_UNLOCK_V3" set "TARGET_DIR=%CD%\TTG_UNLOCK_V3"
if exist "..\scans" set "TARGET_DIR=%CD%\.."

if not exist "%TARGET_DIR%\scans" mkdir "%TARGET_DIR%\scans" >nul 2>&1

set "PYTHON_EXE="
if exist "D:\aimob\hunter\venv\Scripts\python.exe" set "PYTHON_EXE=D:\aimob\hunter\venv\Scripts\python.exe"
if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PYTHON_EXE where py >nul 2>&1 && set "PYTHON_EXE=py"
if not defined PYTHON_EXE where python >nul 2>&1 && set "PYTHON_EXE=python"

if not defined PYTHON_EXE (
  echo [ERROR] Python 3.10 or newer was not found.
  echo Install Python from python.org and enable "Add Python to PATH".
  pause
  exit /b 1
)

echo Python : "%PYTHON_EXE%"
echo Target : "%TARGET_DIR%\scans"
echo.

set "WHEEL="
for %%F in ("%~dp0ttg_device_xray-*.whl") do set "WHEEL=%%~fF"
if not defined WHEEL (
  echo [ERROR] The bundled TTG Device X-Ray wheel is missing.
  echo Extract the complete Windows release ZIP before running this file.
  pause
  exit /b 1
)

set "VENV_DIR=%~dp0.runtime"
if not exist "%VENV_DIR%\Scripts\python.exe" (
  echo [SETUP] Creating the local X-Ray runtime...
  "%PYTHON_EXE%" -m venv "%VENV_DIR%"
  if errorlevel 1 goto :failed
)

set "RUNTIME_PY=%VENV_DIR%\Scripts\python.exe"
echo [SETUP] Installing bundled X-Ray and dependencies...
"%RUNTIME_PY%" -m pip install --disable-pip-version-check --upgrade pip >nul
"%RUNTIME_PY%" -m pip install --disable-pip-version-check --upgrade "%WHEEL%"
if errorlevel 1 goto :failed

echo.
echo [SCAN] Connect one device, authorize USB debugging when requested,
echo        or place the device in its supported service mode.
echo.
"%VENV_DIR%\Scripts\ttg-xray.exe" scan --output "%TARGET_DIR%\scans"
if errorlevel 1 goto :failed

echo.
echo [OK] X-Ray scan bundle created in:
echo      "%TARGET_DIR%\scans"
echo.
echo You can now run TTG UNLOCK V3 again.
pause
exit /b 0

:failed
echo.
echo [ERROR] X-Ray setup or scanning failed. Review the message above.
pause
exit /b 1
