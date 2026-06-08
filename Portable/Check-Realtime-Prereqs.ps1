$ErrorActionPreference = "SilentlyContinue"

$base = Split-Path -Parent $MyInvocation.MyCommand.Path
$candidates = @(
    (Join-Path $base "Tools\Wireshark\tshark.exe"),
    (Join-Path $base "Tools\TShark\tshark.exe"),
    (Join-Path $base "tshark.exe"),
    "$env:ProgramFiles\Wireshark\tshark.exe",
    "${env:ProgramFiles(x86)}\Wireshark\tshark.exe"
)

$pathTshark = Get-Command tshark.exe | Select-Object -ExpandProperty Source -First 1
$tshark = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $tshark) { $tshark = $pathTshark }

Write-Host "Denia realtime prerequisite check" -ForegroundColor Cyan
Write-Host ""

if ($tshark) {
    Write-Host "[OK] tshark found: $tshark" -ForegroundColor Green
    & $tshark -v | Select-Object -First 1
    Write-Host ""
    Write-Host "Capture interfaces:" -ForegroundColor Cyan
    & $tshark -D
} else {
    Write-Host "[MISSING] tshark.exe not found." -ForegroundColor Yellow
    Write-Host "Install Wireshark or place tshark.exe under Tools\Wireshark beside the EXE."
}

Write-Host ""
$npcapService = Get-Service npcap
$npcapLoopback = Get-Service npcap_wifi
if ($npcapService -or $npcapLoopback) {
    Write-Host "[OK] Npcap service detected." -ForegroundColor Green
} else {
    Write-Host "[MISSING] Npcap service not detected." -ForegroundColor Yellow
    Write-Host "Realtime capture usually requires installing Npcap/Wireshark and sometimes running the app as Administrator."
}

Write-Host ""
Read-Host "Press Enter to close"
