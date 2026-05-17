@echo off
:: ============================================================
::  DEVICE SCANNER — ONE CLICK LAUNCHER
::  Right-click this file → "Run as administrator"
:: ============================================================

title Device Scanner Launcher
color 0A

echo.
echo  =============================================
echo   DEVICE SCANNER — AUTO LAUNCHER
echo  =============================================
echo.

:: ── Check for admin rights ──────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Not running as Administrator!
    echo.
    echo  Please right-click this file and choose
    echo  "Run as administrator"
    echo.
    pause
    exit /b 1
)
echo  [OK] Running as Administrator

:: ── Find Python ─────────────────────────────────────────────
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python not found in PATH.
    echo  Make sure Python is installed and added to PATH.
    pause
    exit /b 1
)
echo  [OK] Python found

:: ── Change to script directory ──────────────────────────────
cd /d "%~dp0"
echo  [OK] Working directory: %~dp0

:: ── Step 1: Run check_and_fix.py ────────────────────────────
echo.
echo  =============================================
echo   STEP 1 — Running setup check...
echo  =============================================
echo.
python check_and_fix.py
echo.
echo  [OK] Setup check done.
timeout /t 2 /nobreak >nul

:: ── Step 2: Open dashboard in browser ───────────────────────
echo.
echo  =============================================
echo   STEP 2 — Opening dashboard in browser...
echo  =============================================
echo.
start "" "http://localhost:8000/dashboard.html"
echo  [OK] Browser launched (will load once server starts)
timeout /t 1 /nobreak >nul

:: ── Step 3: Start HTTP server in new window ──────────────────
echo.
echo  =============================================
echo   STEP 3 — Starting HTTP server on port 8000
echo  =============================================
echo.
start "Device Scanner — HTTP Server" cmd /k "cd /d "%~dp0" && echo  [HTTP] Server running at http://localhost:8000 && echo  [HTTP] Keep this window open && echo. && python -m http.server 8000"
echo  [OK] HTTP server started
timeout /t 2 /nobreak >nul

:: ── Step 4: Start scanner in this window ─────────────────────
echo.
echo  =============================================
echo   STEP 4 — Starting scanner (Ctrl+C to stop)
echo  =============================================
echo.
echo  Dashboard: http://localhost:8000/dashboard.html
echo.
python scanner.py

:: ── Scanner stopped (Ctrl+C pressed) ────────────────────────
echo.
echo  =============================================
echo   Scanner stopped.
echo   Close the HTTP server window manually.
echo  =============================================
echo.
pause
