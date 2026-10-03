# Automated Setup Script for reverse-engineering-mcp (Windows PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Reverse Engineering MCP Server — Automated Installer" -ForegroundColor Cyan
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
npm test
npm run build
Write-Host "[+] Build succeeded! Artifacts available in ./dist" -ForegroundColor Green

$serverJsPath = Join-Path $scriptDir "dist\index.js"

# 3. Configure Antigravity / Gemini
$geminiConfigDir = Join-Path $env:USERPROFILE ".gemini\config"
$geminiConfigFile = Join-Path $geminiConfigDir "mcp_config.json"
if (Test-Path $geminiConfigFile) {
    try {
        Write-Host "`n[*] Configuring Antigravity MCP ($geminiConfigFile)..." -ForegroundColor Yellow
        $cfg = Get-Content $geminiConfigFile -Raw | ConvertFrom-Json
        if (-not $cfg.mcpServers) {
            $cfg | Add-Member -Name "mcpServers" -MemberType NoteProperty -Value ([PSCustomObject]@{})
        }
        $cfg.mcpServers | Add-Member -Name "reverse-engineering" -MemberType NoteProperty -Value ([PSCustomObject]@{
            command = "node"
            args = @($serverJsPath)
            env = [PSCustomObject]@{
                CDP_HOST = "127.0.0.1"
                CDP_PORT = "9222"
            }
        }) -Force
        $cfg | ConvertTo-Json -Depth 10 | Set-Content $geminiConfigFile -Encoding UTF8
        Write-Host "[+] Registered in Antigravity config successfully!" -ForegroundColor Green
    } catch {
        Write-Warning "[!] Could not automatically update $geminiConfigFile: $_"
    }
}

# 4. Configure Codex
$codexConfigFile = Join-Path $env:USERPROFILE ".codex\config.toml"
if (Test-Path $codexConfigFile) {
    try {
        Write-Host "`n[*] Configuring Codex MCP ($codexConfigFile)..." -ForegroundColor Yellow
        $codexContent = Get-Content $codexConfigFile -Raw
        if ($codexContent -notmatch '\[mcp_servers\.reverse-engineering\]') {
            $tomlBlock = @"

[mcp_servers.reverse-engineering]
command = "node"
args = ["$($serverJsPath.Replace('\', '\\'))"]
startup_timeout_sec = 60
[mcp_servers.reverse-engineering.env]
CDP_HOST = "127.0.0.1"
CDP_PORT = "9222"
"@
            Add-Content -Path $codexConfigFile -Value $tomlBlock -Encoding UTF8
            Write-Host "[+] Registered in Codex config successfully!" -ForegroundColor Green
        } else {
            Write-Host "[+] reverse-engineering already configured in Codex config." -ForegroundColor Green
        }
    } catch {
        Write-Warning "[!] Could not automatically update $codexConfigFile: $_"
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "   INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "To use reverse-engineering-mcp, start Chrome or Edge with CDP enabled:"
Write-Host "chrome.exe --remote-debugging-port=9222 --user-data-dir=`"$env:TEMP\chrome-cdp`"" -ForegroundColor Yellow
Write-Host "`nThen connect to target tab via browser_targets -> browser_attach."
