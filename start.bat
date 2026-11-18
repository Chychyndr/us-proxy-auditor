@echo off
setlocal
cd /d "%~dp0"
where go >nul 2>nul
if errorlevel 1 (
  echo Go was not found. Install Go from https://go.dev/dl/
  echo Then reopen this terminal and try again.
  pause
  exit /b 1
)
go run . --limit 1500 --concurrency 128 --timeout 5 --rounds 3 --check-google --check-headers %*
set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo Scan finished. Results are stored in the results folder.
pause
exit /b %EXIT_CODE%
