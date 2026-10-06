# Automated Setup Script for Netvein MCP (Windows PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         Netvein MCP — Automated Setup & Installer       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Node.js
Write-Host "`n[*] Checking Node.js installation..." -ForegroundColor Yellow
try {
    $nodeVersion = node -v
    Write-Host "[+] Found Node.js: $nodeVersion" -ForegroundColor Green
    $majorVersion = [int]($nodeVersion -replace '^v(\d+)\..*', '$1')
    if ($majorVersion -lt 20) {
        Write-Warning "[!] Warning: Node.js version 20 or newer is strongly recommended."
    }
} catch {
    Write-Error "[x] Node.js is not found in PATH. Please install Node.js (>= 20) from https://nodejs.org/"
    exit 1
}

# 2. Install dependencies & build
Write-Host "`n[*] Installing dependencies & compiling TypeScript..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -Path $scriptDir

npm install
npm run build
Write-Host "[+] Build succeeded! Artifacts available in ./dist" -ForegroundColor Green

# 3. Configure AI agents via built-in installer
Write-Host "`n[*] Auto-configuring MCP server into detected AI agents..." -ForegroundColor Yellow
node dist/index.js install

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "   INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Netvein MCP server is now ready!"
Write-Host "- Auto-launches Chrome/Edge on port 9222 upon tool invocation."
Write-Host "- Initialize workspace: netvein init (or npx netvein-mcp init)"
Write-Host "- Check workspace:      netvein status"
