$ErrorActionPreference = "Stop"

Write-Host "This installs Wireshark, which includes TShark and can install Npcap." -ForegroundColor Cyan
Write-Host "Run this script as Administrator for best results." -ForegroundColor Yellow
Write-Host ""

$winget = Get-Command winget.exe -ErrorAction SilentlyContinue
if (-not $winget) {
    Write-Host "winget was not found. Please install Wireshark manually from https://www.wireshark.org/" -ForegroundColor Red
    Read-Host "Press Enter to close"
    exit 1
}

winget install --id WiresharkFoundation.Wireshark -e --accept-source-agreements --accept-package-agreements

Write-Host ""
Write-Host "After installation, reopen Denia and click Refresh NICs." -ForegroundColor Green
Read-Host "Press Enter to close"
