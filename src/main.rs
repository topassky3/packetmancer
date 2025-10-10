use clap::Parser;
use serde_json::Value;

mod detectors;
mod engine;
mod network;

use detectors::tcp_health::TcpHealthDetector;
use engine::Engine;

#[derive(Parser, Debug)]
#[command(version, about = "PacketMancer - Analizador de Red Inteligente", long_about = None)]
struct Args {
    /// Ruta al archivo .pcap/.pcapng
    #[arg(short, long)]
    file: String,

    /// Escribe reporte JSON en la ruta indicada (opcional)
    #[arg(long)]
    json: Option<String>,

    /// Número de flujos a mostrar en el Top (por consola). Default: 5
    #[arg(long, default_value_t = 5)]
    top: usize,
}

fn main() {
    let args = Args::parse();
    println!("Iniciando análisis del archivo: {}", &args.file);

    let mut engine = Engine::new();
    engine.register(TcpHealthDetector::new());

    match engine.run(&args.file) {
        Ok(report) => {
            if let Some(path) = args.json.as_ref() {
                if let Err(e) = std::fs::write(path, report.to_string()) {
                    eprintln!("⚠️  No se pudo escribir JSON en {path}: {e}");
                } else {
                    println!("✅ Reporte JSON escrito en: {path}");
                }
            }

            // Salida HUMANA por defecto
            print_human_tcp_health(&report, args.top);

            println!("\n--- ANÁLISIS COMPLETADO ---");
        }
        Err(e) => {
            eprintln!("\n--- ERROR ---");
            eprintln!("No se pudo procesar el archivo: {e}");
        }
    }
}

fn print_human_tcp_health(report: &Value, top_n: usize) {
    println!("\n--- Reporte del Detector de Salud TCP ---");

    // Resumen global
    if let Some(summary) = report.get("summary") {
        let file = summary
            .get("file")
            .and_then(|v| v.as_str())
            .unwrap_or("<desconocido>");
        let pkts = summary
            .get("packets_total")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let schema = summary
            .get("schema")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let dur_ms = summary
            .get("duration_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let thr = summary
            .get("throughput_mbps")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        println!(
            "Archivo: {file} | Paquetes: {pkts} | Duración: {dur_ms} ms | Tasa: {thr:.2} Mbps | Schema: {schema}"
        );
    }

    let tcp = &report["detectors"]["tcp_health"];
    let convs = tcp["conversations_total"].as_u64().unwrap_or(0);
    println!("Se encontraron {convs} conversaciones TCP distintas.");

    // Top por severidad
    println!("\nTop {top_n} conversaciones por SEVERIDAD:");
    if let Some(arr) = tcp["top_by_severity"].as_array() {
        for entry in arr.iter().take(top_n) {
            let flow = entry["flow"].as_str().unwrap_or("");
            let level = entry["score"]["level"].as_str().unwrap_or("BAJA");
            let score = entry["score"]["value"].as_u64().unwrap_or(0);

            let c2s = &entry["c2s"];
            let s2c = &entry["s2c"];

            println!("  - [{level} | score={score}] {flow}");
            println!(
                "    -> C->S: Pkts: {}, Retrans.: {}, Fuera de Orden: {}, Ventana0: {}, DupACK(ev≥3): {}",
                c2s["packets"], c2s["retransmissions"], c2s["out_of_order"], c2s["zero_window_events"], c2s["duplicate_ack_events"]
            );
            println!(
                "    <- S->C: Pkts: {}, Retrans.: {}, Fuera de Orden: {}, Ventana0: {}, DupACK(ev≥3): {}",
                s2c["packets"], s2c["retransmissions"], s2c["out_of_order"], s2c["zero_window_events"], s2c["duplicate_ack_events"]
            );

            // RTT si hay muestras
            let c2s_rtt = &c2s["rtt_ms"];
            let s2c_rtt = &s2c["rtt_ms"];
            let c2s_n = c2s_rtt.get("samples").and_then(|v| v.as_u64()).unwrap_or(0);
            let s2c_n = s2c_rtt.get("samples").and_then(|v| v.as_u64()).unwrap_or(0);
            if c2s_n > 0 || s2c_n > 0 {
                println!(
                    "    RTT C->S: p50={:.1} ms, p95={:.1} ms (n={})",
                    c2s_rtt.get("p50").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    c2s_rtt.get("p95").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    c2s_n
                );
                println!(
                    "    RTT S->C: p50={:.1} ms, p95={:.1} ms (n={})",
                    s2c_rtt.get("p50").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    s2c_rtt.get("p95").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    s2c_n
                );
            }

            if let Some(reasons) = entry["reasons"].as_array() {
                if !reasons.is_empty() {
                    let pretty: Vec<String> = reasons
                        .iter()
                        .filter_map(|r| r.as_str().map(|s| s.to_string()))
                        .collect();
                    println!("    Razones: {}", pretty.join(" · "));
                }
            }
        }
    }
}
