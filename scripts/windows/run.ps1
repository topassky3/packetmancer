# scripts/windows/run.ps1
# Lanza packetmancer asegurando PATH de Npcap y compilando si falta el binario.

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$exe  = Join-Path $root "target\release\packetmancer.exe"

# Añade la carpeta de Npcap al PATH si existe
$npcapCandidates = @("$env:SystemRoot\System32\Npcap", "C:\Windows\System32\Npcap")
foreach ($p in $npcapCandidates) {
  if (Test-Path $p) { $env:Path = "$env:Path;$p" }
}

# Si no existe el binario, construimos en release
if (-not (Test-Path $exe)) {
  Write-Host "No existe el binario en: $exe" -ForegroundColor Yellow
  Write-Host "Compilando (cargo build --release)..." -ForegroundColor Yellow
  Push-Location $root
  cargo build --release
  Pop-Location
}

# Ejecuta con los argumentos que le pases al script
& $exe @args

