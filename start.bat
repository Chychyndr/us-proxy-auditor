@echo off
chcp 65001 >nul
cd /d "%~dp0"
where uv >nul 2>nul
if errorlevel 1 (
  echo uv was not found. Install it from https://docs.astral.sh/uv/getting-started/installation/
  pause
  exit /b 1
)
uv run us_proxy_auditor.py --limit 1500 --concurrency 45 --timeout 5 --rounds 3 --check-google --check-headers %*
echo.
echo Results are saved in the results folder.
pause
