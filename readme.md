# PacketMancer

**Del .pcap al diagnóstico accionable en un solo comando.**

[![CI](https://github.com/topassky3/packetmancer/actions/workflows/ci.yml/badge.svg)](https://github.com/topassky3/packetmancer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)

---

## 🎯 ¿Qué es PacketMancer?

PacketMancer es una herramienta de código abierto para el análisis de red (Rust). Automatiza el **primer nivel de diagnóstico**
sobre capturas `.pcap/.pcapng`, para que te enfoques en **resolver** problemas, no en **encontrarlos**.

---

## ✨ Características (MVP)

- **Detector de Salud TCP**: retransmisiones, fuera de orden, ventana cero, eventos de ACK duplicado (≥3).
- **Scoring por severidad**: ALTA / MEDIA / BAJA.
- **Rendimiento**: procesamiento en streaming (no carga toda la captura a memoria).
- **Salida dual**: humana en consola + **JSON** integrable.

---

## 🚀 Empezando

### Requisitos generales

- **Rust** (toolchain MSVC en Windows):  
  ```powershell
  rustup default stable-x86_64-pc-windows-msvc
  ```
- **libpcap / Npcap**:
  - Linux/WSL/macOS: **libpcap**
  - Windows nativo: **Npcap (runtime)** + **Npcap SDK** (para enlazado al compilar)

### Instalar Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Instalar libpcap (Linux/WSL/macOS)

**Debian/Ubuntu:**
```bash
sudo apt-get update && sudo apt-get install -y libpcap-dev
```

**Fedora/CentOS:**
```bash
sudo dnf install -y libpcap-devel
```

**macOS (Homebrew):**
```bash
brew install libpcap
```

### Clonar y compilar

```bash
git clone https://github.com/topassky3/packetmancer.git
cd packetmancer
cargo build --release
```
El binario queda en `target/release/packetmancer` (o `.exe` en Windows).

---

## 🖥️ Uso (CLI)

```bash
cargo run --release -- --file /ruta/a/tu/captura.pcap
```

**Opciones:**

| Opción         | Descripción                                                 |
|----------------|-------------------------------------------------------------|
| `--file PATH`  | Ruta `.pcap/.pcapng` **(obligatoria)**                      |
| `--json PATH`  | Exporta el reporte JSON                                     |
| `--top N`      | Cuántos flujos mostrar en consola (por defecto: 5)          |

**Ejemplo:**
```bash
cargo run --release -- --file captures/tcp-ecn-sample.pcap --top 5
```

**Exportar JSON:**
```bash
cargo run --release -- --file captures/tcp-ecn-sample.pcap --json report.json
```

---

## 🪟 Windows

### Opción A: WSL (recomendada)

Si tu repo está en Windows (p. ej. `C:\Users\...`), desde WSL:

```bash
cd "/mnt/c/Users/tu_usuario/.../packetmancer"
cargo run --release -- --file captures/tcp-ecn-sample.pcap
```

### Opción B: Windows nativo (probado)

**1) Pre-requisitos**

- **Visual C++ Build Tools** (toolchain MSVC para Rust).
- **Npcap (runtime)** y **Npcap SDK** instalados.
- Este repo trae `build.rs` que en Windows añade el **search path** del SDK.  
  - Por defecto asume `C:\NpcapSDK`.  
  - Puedes **override** con `NPCAP_SDK_DIR` (ej. `D:\SDKs\Npcap`).

**2) Compilar**

```powershell
cargo build --release
```

> ⚠️ **Permisos (Admin)**  
> - **Compilar**: normalmente **NO** requiere Administrador.  
>   Si solo te compila como Admin, suele ser por “Carpetas controladas”/antivirus o por permisos raros de la ruta:
>   - Mueve el repo a una carpeta de usuario estándar (ej. `C:\Users\Tú\src\packetmancer`)
>   - Permite `cargo.exe`/`rustc.exe` en tu antivirus/Defender
>   - Evita rutas muy largas o con espacios extraños
>
> - **Ejecutar** analizando archivos `.pcap`: **NO** requiere Admin.  
> - **Captura en vivo** con Npcap: puede requerir Admin **solo si** instalaste Npcap con
>   “**Restrict Npcap driver to Administrators only**”. Reinstala desmarcando esa opción para usarlo sin Admin.

**3) Scripts útiles** (incluidos en `scripts/windows`)

> Si PowerShell bloquea scripts, habilítalos **solo para esta sesión**:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
> ```

- **Verificar Npcap**
  ```powershell
  .\scripts\windows\check_npcap.ps1
  # -> "Npcap Runtime OK." si todo bien
  ```

- **Lanzador del binario** (auto-compila si falta y añade PATH de Npcap)
  ```powershell
  .\scripts\windows\run.ps1 --file .\captures\tcp-ecn-sample.pcap
  ```

**Contenido de los scripts (referencia):**

`scripts/windows/check_npcap.ps1`
```powershell
# check_npcap.ps1 - Verifica presencia básica de Npcap Runtime
$paths = @(
  "$env:SystemRoot\System32\Npcap\wpcap.dll",
  "$env:SystemRoot\System32\Npcap\Packet.dll"
)
$ok = $true
foreach ($p in $paths) {
  if (-not (Test-Path $p)) { $ok = $false }
}
if ($ok) { "Npcap Runtime OK." } else { throw "Npcap Runtime NO encontrado. Instala Npcap (runtime)." }
```

`scripts/windows/run.ps1`
```powershell
# Lanza packetmancer asegurando PATH de Npcap y compilando si falta el binario.
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$exe  = Join-Path $root "target\release\packetmancer.exe"

# Añade la carpeta de Npcap al PATH si existe
$npcapCandidates = @("$env:SystemRoot\System32\Npcap", "C:\Windows\System32\Npcap")
foreach ($p in $npcapCandidates) { if (Test-Path $p) { $env:Path = "$env:Path;$p" } }

# Compila si el binario no existe
if (-not (Test-Path $exe)) {
  Write-Host "No existe el binario en: $exe" -ForegroundColor Yellow
  Write-Host "Compilando (cargo build --release)..." -ForegroundColor Yellow
  Push-Location $root
  cargo build --release
  Pop-Location
}

# Ejecuta con los argumentos que le pases al script
& $exe @args
```

> Si tu SDK no está en `C:\NpcapSDK`, define la variable y compila:
> ```powershell
> $env:NPCAP_SDK_DIR = "D:\SDKs\Npcap"
> cargo build --release
> ```

---

## 🧱 Estructura del proyecto

```
src/
├─ main.rs                # CLI, parseo de flags, salida humana
├─ engine.rs              # Orquestación de detectores
├─ detectors/
│  └─ tcp_health.rs       # Detector de Salud TCP (scoring, métricas, JSON, tests)
└─ network/
   ├─ mod.rs
   └─ flow.rs             # 5-tupla simplificada + reverse()
build.rs                  # (Windows) link-search a Npcap SDK Lib\x64
scripts/windows/*.ps1     # check_npcap / run helpers
captures/                 # pcaps de ejemplo (pequeños)
```

---

## 🗺️ Roadmap (resumen)

- RTT/latencia p50/p95 por conversación
- Detectores DNS (latencia, NXDOMAIN, DGA/punycode)
- Filtros CLI y perfiles
- Releases con binarios firmados (multiplataforma)

---

## 🧪 Calidad (desarrollo)

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test --all-features
```

---

## 🤝 Contribuir

- Abre **issues** con pasos y, si puedes, un `.pcap` reducido.
- Propón detectores/reglas nuevas en issues.
- Para PRs: discútelo en un issue y deja `fmt`, `clippy`, `test` en verde.

---

## 🧪 CI / Compatibilidad

- **Linux/macOS**: ✅ Build · ✅ Clippy · ✅ Tests  
- **Windows**: ✅ Build · ✅ Clippy · (Tests limitados)  
  Mejor experiencia: **WSL**.

---

## 📄 Licencia

MIT

---

## 👤 Autor

**Juan Felipe Orozco Cortes**  
Blog: *La Verdad en los Paquetes*  
GitHub: **@topassky3**

<div align="center">
  <sub>Construido con ❤️ y Rust 🦀</sub>
</div>
