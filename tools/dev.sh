#!/usr/bin/env bash
# Guardian developer tools launcher.
#
# Usage:
#   bash tools/dev.sh
#
# Activates the virtual environment (if present), starts the dev server,
# and opens http://localhost:8765 in the default browser.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Activate virtual environment if available
for venv_dir in .venv venv; do
  if [[ -f "$venv_dir/bin/activate" ]]; then
    # shellcheck disable=SC1090
    source "$venv_dir/bin/activate"
    echo "[guardian] Activated virtualenv: $venv_dir"
    break
  fi
done

echo "[guardian] Starting dev server on http://localhost:8765 …"

# Start server in foreground (Ctrl+C to stop)
# Open browser after a short delay so the server has time to bind
(
  sleep 1
  if   command -v open     &>/dev/null; then open     "http://localhost:8765"   # macOS
  elif command -v xdg-open &>/dev/null; then xdg-open "http://localhost:8765"   # Linux
  fi
) &

python tools/dev_server.py
