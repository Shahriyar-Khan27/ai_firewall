@echo off
setlocal

REM Build a standalone guard.exe via PyInstaller. Run from the project root.

cd /d "%~dp0\.."

python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e ".[dev,mcp]"
python -m pip install --quiet pyinstaller

python -m PyInstaller ^
  --noconfirm ^
  --onefile ^
  --name guard ^
  --add-data "ai_firewall/config/default_rules.yaml;ai_firewall/config" ^
  --hidden-import bashlex ^
  --hidden-import sqlglot ^
  --hidden-import mcp ^
  --hidden-import mcp.server.fastmcp ^
  ai_firewall\cli\main.py

echo.
echo built: dist\guard.exe
