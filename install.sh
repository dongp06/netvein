#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "   Reverse Engineering MCP Server — Automated Installer"
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

echo "[*] Running unit and smoke tests..."
npm test

echo "[*] Building TypeScript source..."
npm run build

SERVER_JS_PATH="$SCRIPT_DIR/dist/index.js"
echo "[+] Build complete: $SERVER_JS_PATH"

# Setup Claude Code / Claude Desktop config if exists
CLAUDE_CONFIG="$HOME/.config/Claude/claude_desktop_config.json"
if [ -f "$CLAUDE_CONFIG" ]; then
    echo "[*] Found Claude Desktop configuration at $CLAUDE_CONFIG"
    echo "[i] You can register reverse-engineering by adding to mcpServers in $CLAUDE_CONFIG"
fi

echo "=========================================================="
echo "   INSTALLATION COMPLETE!"
echo "=========================================================="
echo "To start Chromium with CDP:"
echo "google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp"
