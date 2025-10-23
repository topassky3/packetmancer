# PacketMancer

<p align="center">
  <img src="assets/packetmancer-demo.min.gif" alt="PacketMancer demo (CLI)" />
</p>


**Del .pcap al diagnÃ³stico accionable en un solo comando.**

[![CI](https://github.com/topassky3/packetmancer/actions/workflows/ci.yml/badge.svg)](https://github.com/topassky3/packetmancer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)

---

## ðŸŽ¯ Â¿QuÃ© es PacketMancer?

PacketMancer es una herramienta de cÃ³digo abierto para el anÃ¡lisis de red, escrita en Rust. Nace de la frustraciÃ³n de pasar horas buscando la aguja en el pajar digital que son las capturas de paquetes. Su misiÃ³n es **automatizar el primer nivel de diagnÃ³stico**, permitiendo a los ingenieros enfocarse en resolver problemas, no en encontrarlos.

Este proyecto se estÃ¡ construyendo en pÃºblico. Puedes seguir el viaje, los desafÃ­os tÃ©cnicos y las decisiones de diseÃ±o en mi blog: **La Verdad en los Paquetes**.

---

## âœ¨ CaracterÃ­sticas Principales (MVP Actual)

### ðŸ” AnÃ¡lisis de Salud TCP
Identifica problemas de salud en conversaciones TCP, incluyendo:
- **Retransmisiones** - Paquetes reenviados por pÃ©rdida
- **Paquetes Fuera de Orden** - Desorden en la secuencia TCP
- **Eventos de Ventana Cero** - Bloqueos de flujo por congestiÃ³n
- **Eventos de ACK Duplicado** - Indicador de pÃ©rdida de paquetes (â‰¥3 eventos)

### ðŸŽ¯ Sistema de Scoring por Severidad
Clasifica conversaciones automÃ¡ticamente:
- **ALTA** (score â‰¥ 100): Problemas crÃ­ticos que requieren atenciÃ³n inmediata
- **MEDIA** (50-99): DegradaciÃ³n notable del rendimiento
- **BAJA** (1-49): AnomalÃ­as menores

### âš¡ Rendimiento
- **Procesamiento en streaming**: Lee archivos `.pcap` y `.pcapng` sin cargar todo en memoria
- **AnÃ¡lisis de capturas de varios GB** sin agotar recursos
- **Motor modular**: Arquitectura extensible para aÃ±adir nuevos detectores (DNS, HTTP, etc.)

### ðŸ“Š Salida Dual
- **Reporte legible para humanos** en consola con colores y formato claro
- **Salida estructurada en JSON** para integraciÃ³n con scripts y herramientas

---

## ðŸš€ Empezando

### Requisitos

- **Rust** (via `rustup`)
- **libpcap** (Linux/WSL/macOS). **En Windows nativo se usa Npcap SDK.**

### Instalar Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
> En Windows, instala con el instalador de Rust oficial o con `rustup-init.exe`.

### Instalar libpcap / Npcap

**Debian/Ubuntu/WSL:**
```bash
sudo apt-get update && sudo apt-get install -y libpcap-dev
```

**Fedora/CentOS:**
```bash
sudo dnf install -y libpcap-devel
```

**macOS:**
```bash
brew install libpcap
```

**Windows (nativo):**
```powershell
choco install npcap -y --params '"/winpcap_mode=yes /npf_startup=yes"'
choco install npcap-sdk -y
# (opcional) si el SDK no estÃ¡ en C:\NpcapSDK
$env:NPCAP_SDK_DIR = "C:\Ruta\NpcapSDK"
```

### Clonar y Compilar

```bash
git clone https://github.com/topassky3/packetmancer.git
cd packetmancer
```

**Linux / macOS / WSL:**
```bash
cargo build --release
```
El binario quedarÃ¡ en `target/release/packetmancer` (o `.exe` en Windows).

> **âš ï¸ Windows nativo (importante):** en varios entornos, la primera compilaciÃ³n necesita una consola **elevada**.  
> Abre **PowerShell** como *â€œEjecutar como administradorâ€* y ejecuta:
> ```powershell
> cargo build --release
> ```
> Si la compilaciÃ³n falla sin privilegios elevados (errores de permisos/enlace), vuelve a intentarlo con PowerShell **Administrador**.  
> AsegÃºrate tambiÃ©n de que el SDK exista en `C:\NpcapSDK\Lib\x64` o fija `NPCAP_SDK_DIR` como se indicÃ³ arriba.

---

## ðŸ–¥ï¸ Uso (CLI)

### Comando BÃ¡sico

```bash
cargo run --release -- --file /ruta/a/tu/captura.pcap
```

### Opciones Principales

| OpciÃ³n | DescripciÃ³n |
|--------|-------------|
| `--file <PATH>` | Ruta al archivo `.pcap`/`.pcapng` **(obligatoria)** |
| `--json <PATH>` | Exporta el reporte JSON a ese archivo |
| `--top <N>` | CuÃ¡ntos flujos mostrar en consola (por defecto: 5) |

### Ejemplo Real

```bash
cargo run -- --file captures/tcp-ecn-sample.pcap --top 5
```

**Salida (ejemplo):**
```
Iniciando anÃ¡lisis del archivo: captures/tcp-ecn-sample.pcap

--- Reporte del Detector de Salud TCP ---
Archivo: captures/tcp-ecn-sample.pcap | Paquetes: 479 | DuraciÃ³n: 59 ms | Tasa: 16.13 Mbps | Schema: v1
Se encontraron 1 conversaciones TCP distintas.

Top 5 conversaciones por SEVERIDAD:
  - [MEDIA | score=80] 1.1.23.3:46557 <-> 1.1.12.1:80/TCP
    -> C->S: Pkts: 309, Retrans.: 1, Fuera de Orden: 0, Ventana0: 0, DupACK(evâ‰¥3): 29
    <- S->C: Pkts: 170, Retrans.: 0, Fuera de Orden: 0, Ventana0: 0, DupACK(evâ‰¥3): 0
    Razones: eventos de ACK duplicado (â‰¥3) (29)

--- ANÃLISIS COMPLETADO ---
```

### Exportar a JSON

```bash
cargo run -- --file captures/tcp-ecn-sample.pcap --json report.json
```

**Ejemplo de JSON (recortado):**
```json
{
  "summary": {
    "schema": "v1",
    "file": "captures/tcp-ecn-sample.pcap",
    "packets_total": 479,
    "duration_ms": 59
  },
  "detectors": {
    "tcp_health": {
      "conversations_total": 1,
      "top_by_severity": [
        {
          "flow": "1.1.23.3:46557 <-> 1.1.12.1:80/TCP",
          "score": { "value": 80, "level": "MEDIA" }
        }
      ]
    }
  }
}
```

---

## ðŸªŸ GuÃ­a RÃ¡pida WSL (Windows)

Si tu repositorio estÃ¡ en Windows (por ejemplo: `C:\Users\usuario\...\packetmancer`), accede desde WSL/Ubuntu:

```bash
cd "/mnt/c/Users/usuario/Desktop/packetmancer"
cargo run -- --file captures/tcp-ecn-sample.pcap
```

**ðŸ’¡ Tip:** Si ves errores de permisos al acceder a rutas de Windows, revisa comillas y espacios, o mueve las capturas a una ruta sin espacios.

---

## ðŸ§± Estructura del Proyecto

```
src/
â”œâ”€ main.rs                # CLI, parseo de flags, salida humana
â”œâ”€ engine.rs              # Engine: registro y orquestaciÃ³n de detectores
â”œâ”€ detectors/
â”‚  â””â”€ tcp_health.rs       # Detector de Salud TCP (scoring, mÃ©tricas, JSON, tests)
â””â”€ network/
   â”œâ”€ mod.rs
   â””â”€ flow.rs             # DefiniciÃ³n de Flow (5-tupla simplificada) + reverse()
```

---

## ðŸ—ºï¸ Roadmap

### Inmediato (MVP)

- [ ] RTT/latencia (p50/p95) por conversaciÃ³n (Story #2)
- [ ] Detectores DNS (latencia, NXDOMAIN, DGA/punycode) y Conversations (top por bytes/paquetes)
- [ ] CLI avanzado: Filtros (`--filter`, `--dns-latency-threshold`, `--no-detector tcp_health`) y perfiles
- [ ] Releases: Binarios multiplataforma

### FilosofÃ­a de Desarrollo

**Cero falsos positivos** siempre que sea posible. Umbrales conservadores y precisiÃ³n sobre ruido.

---

## ðŸ§ª Calidad del CÃ³digo (Desarrollo)

Antes de hacer un commit, asegÃºrate de que todo pase:

```bash
# Formateo automÃ¡tico
cargo fmt

# Linting estricto
cargo clippy -- -D warnings

# Ejecutar todas las pruebas
cargo test --all-features
```

---

## ðŸ¤ Contribuir

Â¡Este es un proyecto de cÃ³digo abierto y las contribuciones son bienvenidas!

### Reportar Bugs
Abre un **issue** con:
- Pasos para reproducir el problema
- Adjunta archivos `.pcap` si es posible (o pcaps reducidos/anonimizados)
- VersiÃ³n de Rust y sistema operativo

### Sugerir Funcionalidades
Â¿Tienes una idea para un nuevo detector o regla? Â¡Comenta tu propuesta en un issue!

### Pull Requests
1. **Abre un issue** primero para discutir el cambio
2. AsegÃºrate de que `fmt`, `clippy` y `test` estÃ©n en verde
3. Describe claramente quÃ© problema resuelve tu PR

---

## ðŸ§ª CI / Compatibilidad

- **Linux (Ubuntu)**: âœ… Build Â· âœ… Clippy Â· âœ… Tests
- **macOS**: âœ… Build Â· âœ… Clippy Â· âœ… Tests
- **Windows (experimental)**: âœ… Build Â· âœ… Clippy Â· âŒ Tests (deshabilitados por ahora)  
  Recomendado usar **WSL** para la mejor experiencia.

**Notas CI**
- La matriz de CI estÃ¡ configurada sin *fail-fast*.
- El job de Windows es *best effort* mientras cerramos dependencias.

---

## ðŸªŸ Windows nativo (experimental)

**Resumen rÃ¡pido:**  
1) Instala Npcap + Npcap SDK (ver arriba).  
2) Abre **PowerShell como Administrador**.  
3) Compila:

```powershell
cargo clean
cargo build --release
```

4) Ejecuta (opcional, con script):
```powershell
# Asegura PATH de Npcap
$npcap = "$env:SystemRoot\System32\Npcap"
if (Test-Path $npcap) { $env:Path = "$env:Path;$npcap" }

.\target\release\packetmancer.exe --file .\captures\tcp-ecn-sample.pcap
```

> **Nota:** Si tu SDK no estÃ¡ en `C:\NpcapSDK`, define `NPCAP_SDK_DIR`:
> ```powershell
> $env:NPCAP_SDK_DIR = "D:\SDKs\NpcapSDK"
> ```

---

## ðŸ“„ Licencia

Este proyecto estÃ¡ bajo la **Licencia MIT**.

---

## ðŸ‘¨â€ðŸ’» Autor

**Juan Felipe Orozco Cortes**  
ðŸ“ Blog: *La Verdad en los Paquetes*  
ðŸ’» GitHub: [@topassky3](https://github.com/topassky3)

<div align="center">
  <sub>Construido con â¤ï¸ y Rust ðŸ¦€</sub>
</div>



Add-Content -Path README.md -Value "`n> Prueba rulesets: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
