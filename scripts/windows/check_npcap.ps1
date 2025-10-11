# Comprueba que las DLL de Npcap (wpcap.dll/Packet.dll) estén accesibles
$paths = @("$env:SystemRoot\System32\Npcap", "$env:WINDIR\System32")
$hasWpcap = $false
foreach ($p in $paths) {
  if (Test-Path (Join-Path $p "wpcap.dll")) { $hasWpcap = $true; break }
}

if (-not $hasWpcap) {
  Write-Host "Npcap Runtime no detectado. Instálalo desde https://nmap.org/npcap/ (marca 'Install Npcap for all users')." -ForegroundColor Yellow
  exit 1
} else {
  Write-Host "Npcap Runtime OK." -ForegroundColor Green
}
