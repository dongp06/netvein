#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "         Netvein MCP — Automated Setup & Installer       "
echo "=========================================================="

# Check Node.js
if ! command -v node >/dev/null 2>&1; then
    echo "[x] Error: Node.js is not found in PATH. Install Node.js (>= 20) first."
    exit 1
fi

NODE_VERSION=$(node -v | sed 's/^v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
    echo "[!] Warning: Node.js 20 or newer is recommended. Current: $(node -v)"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Installing dependencies..."
npm install

echo "[*] Building TypeScript source..."
npm run build

echo "[*] Auto-configuring MCP server into detected AI agents..."
node dist/index.js install

echo "=========================================================="
echo "   INSTALLATION COMPLETE!"
echo "=========================================================="
echo "Netvein MCP server is now ready!"
echo "- Auto-launches Chromium on port 9222 upon tool invocation."
echo "- Initialize workspace: netvein init (or npx netvein-mcp init)"
echo "- Check workspace:      netvein status"
