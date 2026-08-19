@echo off
REM ============================================================
REM  Mini SIEM - Windows executable build script
REM  Run from the project folder in a normal (non-admin) prompt.
REM ============================================================

echo [1/4] Checking Python...
python --version || (echo Python not found on PATH. & exit /b 1)

echo.
echo [2/4] Installing build + runtime dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller>=6.15.0 waitress==3.0.2
if errorlevel 1 (echo Dependency install failed. & exit /b 1)

echo.
echo [3/4] Cleaning previous build...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo.
echo [4/4] Building MiniSIEM.exe (this takes 1-3 minutes)...
pyinstaller minisiem.spec --noconfirm
if errorlevel 1 (echo Build failed. & exit /b 1)

echo.
echo ============================================================
echo  Done.  Your executable:  dist\MiniSIEM.exe
echo  Double-click it. The dashboard opens automatically.
echo ============================================================
pause
