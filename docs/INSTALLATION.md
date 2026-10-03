# Installation & Setup Guide

`reverse-engineering-mcp` is a Model Context Protocol (MCP) server that provides AI coding assistants with deep, real-time control over a Chromium browser via the Chrome DevTools Protocol (CDP).

---

## 1. Prerequisites

- **Node.js**: Version 20.x or newer (`node -v`)
- **NPM**: Version 9.x or newer
- **Browser**: Google Chrome, Microsoft Edge, Brave, or Chromium

---

## 2. Fast Automated Setup

### On Windows (PowerShell)
Run the automated installer script:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```
*The installer automatically builds the project, runs the test suite, and registers the server into both Antigravity (`~/.gemini/config/mcp_config.json`) and Codex (`~/.codex/config.toml`).*

### On Linux / macOS (Bash)
```bash
chmod +x install.sh
./install.sh
```

---

## 3. Manual Build & Test

If you prefer building manually from source:

```bash
# Clone and enter directory
cd D:\MCP\reverse-engineering-mcp

# Install dependencies
npm install

# Run automated test suite (19 unit/smoke tests)
npm test

# Typecheck and compile TypeScript
npm run check
npm run build
```

The compiled entrypoint will be generated at `dist/index.js`.

---

## 4. Starting Browser with Remote Debugging (CDP)

The MCP server connects to an existing Chromium instance running with the `--remote-debugging-port` flag enabled.

### Windows (PowerShell / Command Prompt)

**Google Chrome:**
```powershell
& "C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir="$env:TEMP\chrome-cdp-profile" --no-first-run
```

**Microsoft Edge:**
```powershell
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --remote-debugging-port=9222 --user-data-dir="$env:TEMP\edge-cdp-profile" --no-first-run
```

### Linux
```bash
google-chrome --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 --user-data-dir="/tmp/chrome-cdp-profile" --no-first-run
```

### macOS
```bash
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222 --user-data-dir="/tmp/chrome-cdp-profile" --no-first-run
```

> **Security Note:** Always bind remote debugging to `127.0.0.1` (localhost). Never expose port `9222` to untrusted network interfaces.

---

## 5. Client Configuration

### A. Antigravity IDE / Gemini
Edit `~/.gemini/config/mcp_config.json`:

```json
{
  "mcpServers": {
    "reverse-engineering": {
      "command": "node",
      "args": ["D:\\MCP\\reverse-engineering-mcp\\dist\\index.js"],
      "env": {
        "CDP_HOST": "127.0.0.1",
        "CDP_PORT": "9222"
      }
    }
  }
}
```

### B. Codex CLI & Desktop
Edit `~/.codex/config.toml`:

```toml
[mcp_servers.reverse-engineering]
command = "node"
args = ["D:\\MCP\\reverse-engineering-mcp\\dist\\index.js"]
startup_timeout_sec = 60
[mcp_servers.reverse-engineering.env]
CDP_HOST = "127.0.0.1"
CDP_PORT = "9222"
```

### C. Claude Desktop
Edit `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "reverse-engineering": {
      "command": "node",
      "args": ["D:/MCP/reverse-engineering-mcp/dist/index.js"],
      "env": {
        "CDP_HOST": "127.0.0.1",
        "CDP_PORT": "9222"
      }
    }
  }
}
```

### D. Cursor / VS Code (Roo Code / Cline)
Add under MCP server settings:
```json
{
  "name": "reverse-engineering",
  "command": "node",
  "args": ["D:/MCP/reverse-engineering-mcp/dist/index.js"],
  "env": {
    "CDP_HOST": "127.0.0.1",
    "CDP_PORT": "9222"
  }
}
```

---

## 6. Verifying Installation

To test that the MCP server executable starts and loads properly:

```bash
# Print help and usage
node dist/index.js --help

# Output version
node dist/index.js --version
```
