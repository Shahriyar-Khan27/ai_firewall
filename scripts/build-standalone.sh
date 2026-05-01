#!/usr/bin/env bash
# Build a standalone `guard` binary via PyInstaller.
# Run from the project root.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e ".[dev,mcp]"
python -m pip install --quiet pyinstaller

OUT_NAME="guard"
SPEC="$ROOT/scripts/guard.spec"

if [ -f "$SPEC" ]; then
  python -m PyInstaller --noconfirm "$SPEC"
else
  python -m PyInstaller \
    --noconfirm \
    --onefile \
    --name "$OUT_NAME" \
    --add-data "ai_firewall/config/default_rules.yaml:ai_firewall/config" \
    --hidden-import bashlex \
    --hidden-import sqlglot \
    --hidden-import mcp \
    --hidden-import mcp.server.fastmcp \
    ai_firewall/cli/main.py
fi

echo
echo "built: $ROOT/dist/$OUT_NAME$( [ -n "${WINDIR:-}" ] && echo .exe )"
