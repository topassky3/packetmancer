# PacketMancer

**Del .pcap al diagnóstico accionable en un solo comando.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)

---

## 🎯 ¿Qué es PacketMancer?

PacketMancer es una herramienta de código abierto para el análisis de red, escrita en Rust. Nace de la frustración de pasar horas buscando la aguja en el pajar digital que son las capturas de paquetes. Su misión es **automatizar el primer nivel de diagnóstico**, permitiendo a los ingenieros enfocarse en resolver problemas, no en encontrarlos.

Este proyecto se está construyendo en público. Puedes seguir el viaje, los desafíos técnicos y las decisiones de diseño en mi blog: [**La Verdad en los Paquetes**](https://substack.com/home/post/p-175134479).

---

## ✨ Características Principales (MVP Actual)

### 🔍 Análisis de Salud TCP
Identifica problemas de salud en conversaciones TCP, incluyendo:
- **Retransmisiones** - Paquetes reenviados por pérdida
- **Paquetes Fuera de Orden** - Desorden en la secuencia TCP
- **Eventos de Ventana Cero** - Bloqueos de flujo por congestión
- **Eventos de ACK Duplicado** - Indicador de pérdida de paquetes (≥3 eventos)

### 🎯 Sistema de Scoring por Severidad
Clasifica conversaciones automáticamente:
- **ALTA** (score ≥ 100): Problemas críticos que requieren atención inmediata
- **MEDIA** (50-99): Degradación notable del rendimiento
- **BAJA** (1-49): Anomalías menores

### ⚡ Rendimiento
- **Procesamiento en streaming**: Lee archivos `.pcap` y `.pcapng` sin cargar todo en memoria
- **Análisis de capturas de varios GB** sin agotar recursos
- **Motor modular**: Arquitectura extensible para añadir nuevos detectores (DNS, HTTP, etc.)

### 📊 Salida Dual
- **Reporte legible para humanos** en consola con colores y formato claro
- **Salida estructurada en JSON** para integración con scripts y herramientas

---

## 🚀 Empezando

### Requisitos

- **Rust** (via `rustup`)
- **libpcap** (en Linux/WSL; en Windows nativo usar Npcap, pero se recomienda WSL)

### Instalar Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Instalar libpcap

**En Debian/Ubuntu/WSL:**
```bash
sudo apt-get update && sudo apt-get install -y libpcap-dev
```

**En Fedora/CentOS:**
```bash
sudo dnf install -y libpcap-devel
```

**En macOS:**
```bash
brew install libpcap
```

### Clonar y Compilar

```bash
git clone https://github.com/topassky3/packetmancer.git
cd packetmancer
cargo build --release
```

El binario final se encontrará en `target/release/packetmancer`.

---

## 🖥️ Uso (CLI)

### Comando Básico

```bash
cargo run --release -- --file /ruta/a/tu/captura.pcap
```

### Opciones Principales

| Opción | Descripción |
|--------|-------------|
| `--file <PATH>` | Ruta al archivo `.pcap`/`.pcapng` **(obligatoria)** |
| `--json <PATH>` | Exporta el reporte JSON a ese archivo |
| `--top <N>` | Cuántos flujos mostrar en consola (por defecto: 5) |

### Ejemplo Real

```bash
cargo run -- --file captures/tcp-ecn-sample.pcap --top 5
```

**Salida en Consola:**

```
Iniciando análisis del archivo: captures/tcp-ecn-sample.pcap

--- Reporte del Detector de Salud TCP ---
Archivo: captures/tcp-ecn-sample.pcap | Paquetes: 479 | Duración: 59 ms | Tasa: 16.13 Mbps | Schema: v1
Se encontraron 1 conversaciones TCP distintas.

Top 5 conversaciones por SEVERIDAD:
  - [MEDIA | score=80] 1.1.23.3:46557 <-> 1.1.12.1:80/TCP
    -> C->S: Pkts: 309, Retrans.: 1, Fuera de Orden: 0, Ventana0: 0, DupACK(ev≥3): 29
    <- S->C: Pkts: 170, Retrans.: 0, Fuera de Orden: 0, Ventana0: 0, DupACK(ev≥3): 0
    Razones: eventos de ACK duplicado (≥3) (29)

--- ANÁLISIS COMPLETADO ---
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
          "flow": "1.1.23.3:46557  1.1.12.1:80/TCP",
          "score": { "value": 80, "level": "MEDIA" },
          "reasons": [ "eventos de ACK duplicado (≥3) (29)" ],
          "c2s": {
            "packets": 309,
            "retransmissions": 1,
            "out_of_order": 0,
            "zero_window_events": 0,
            "duplicate_ack_events": 29
          },
          "s2c": {
            "packets": 170,
            "retransmissions": 0,
            "out_of_order": 0,
            "zero_window_events": 0,
            "duplicate_ack_events": 0
          }
        }
      ]
    }
  }
}
```

---

## 🪟 Guía Rápida WSL (Windows)

Si tu repositorio está en Windows (por ejemplo: `C:\Users\usuario\...\packetmancer`), accede desde WSL/Ubuntu:

```bash
cd "/mnt/c/Users/usuario/Desktop/packetmancer"
cargo run -- --file captures/tcp-ecn-sample.pcap
```

**💡 Tip:** Si ves errores de permisos al acceder a rutas de Windows, revisa comillas y espacios, o mueve las capturas a una ruta sin espacios.

---

## 🧱 Estructura del Proyecto

```
src/
├─ main.rs                # CLI, parseo de flags, salida humana
├─ engine.rs              # Engine: registro y orquestación de detectores
├─ detectors/
│  └─ tcp_health.rs       # Detector de Salud TCP (scoring, métricas, JSON, tests)
└─ network/
   ├─ mod.rs
   └─ flow.rs             # Definición de Flow (5-tupla simplificada) + reverse()
```

---

## 🗺️ Roadmap

### Inmediato (MVP)

- [ ] **Semana 2–3**: RTT/latencia (p50/p95) por conversación (Story #2)
- [ ] **Semana 4–6**: Detectores DNS (latencia, NXDOMAIN, DGA/punycode) y Conversations (top por bytes/paquetes)
- [ ] **CLI avanzado**: Filtros (`--filter`, `--dns-latency-threshold`, `--no-detector tcp_health`) y perfiles
- [ ] **Releases**: Binarios multiplataforma firmados

### Filosofía de Desarrollo

**Cero falsos positivos** siempre que sea posible. Umbrales conservadores y precisión sobre ruido.

---

## 🧪 Calidad del Código (Desarrollo)

Antes de hacer un commit, asegúrate de que todo pase:

```bash
# Formateo automático
cargo fmt

# Linting estricto
cargo clippy -- -D warnings

# Ejecutar todas las pruebas
cargo test --all-features
```

---

## 🤝 Contribuir

¡Este es un proyecto de código abierto y las contribuciones son bienvenidas!

### Reportar Bugs
Abre un **issue** con:
- Pasos para reproducir el problema
- Adjunta archivos `.pcap` si es posible (o pcaps reducidos/anonimizados)
- Versión de Rust y sistema operativo

### Sugerir Funcionalidades
¿Tienes una idea para un nuevo detector o regla? ¡Comenta tu propuesta en un issue!

### Pull Requests
1. **Abre un issue** primero para discutir el cambio
2. Asegúrate de que `fmt`, `clippy` y `test` estén en verde
3. Describe claramente qué problema resuelve tu PR

---

## 📄 Licencia

Este proyecto está bajo la **Licencia MIT**.

---

## 👨‍💻 Autor

**Juan Felipe Orozco Cortes**  
📝 Blog: [La Verdad en los Paquetes](https://substack.com)  
💻 GitHub: [@topassky3](https://github.com/topassky3)

---

<div align="center">
  <sub>Construido con ❤️ y Rust 🦀</sub>
</div>