#!/usr/bin/env bash
# install.sh — bootstrap Guardian on a fresh system.
#
# Usage:
#   bash install.sh
#
# What this does:
#   1. Checks Python 3.12+
#   2. Installs Python dependencies (requirements.txt)
#   3. Compiles the gRPC proto stubs
#   4. Copies guardian.yaml.example → guardian.yaml (if not already present)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[guardian]${NC} $*"; }
warn()  { echo -e "${YELLOW}[guardian]${NC} $*"; }
error() { echo -e "${RED}[guardian]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Python version check
# ---------------------------------------------------------------------------
info "Checking Python version…"
if ! command -v python3 &>/dev/null; then
  error "python3 not found. Install Python 3.12+ from https://python.org"
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 12 ]]; then
  error "Python 3.12+ required (found $PY_VER). Install from https://python.org"
fi
info "Python $PY_VER — OK"

# ---------------------------------------------------------------------------
# 2. Install dependencies
# ---------------------------------------------------------------------------
info "Installing Python dependencies…"
python3 -m pip install --quiet -r requirements.txt
info "Dependencies installed."

# ---------------------------------------------------------------------------
# 3. Generate proto stubs
# ---------------------------------------------------------------------------
info "Generating gRPC proto stubs…"
bash scripts/gen_proto.sh
info "Proto stubs generated."

# ---------------------------------------------------------------------------
# 4. Copy guardian.yaml.example if needed
# ---------------------------------------------------------------------------
if [[ ! -f guardian.yaml ]]; then
  cp guardian.yaml.example guardian.yaml
  warn "Copied guardian.yaml.example → guardian.yaml"
  warn "Edit guardian.yaml and set your API token from https://viriatosecurity.com"
else
  info "guardian.yaml already exists — skipping copy."
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
info "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit guardian.yaml and set your API token."
echo "  2. Run the agent in dry-run mode to verify:"
echo "       python -m agent.main --fake --dry-run --log-level DEBUG"
echo "  3. Run in production mode (Linux with eBPF in Phase 2):"
echo "       python -m agent.main --config /etc/guardian/guardian.yaml"
echo ""
echo "Docs: https://github.com/Viriato-Security/guardian"
echo "Support: hello@viriatosecurity.com"
