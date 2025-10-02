use clap::Parser;
use serde_json::Value;

mod engine;
mod detectors;
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
                    eprintln!("⚠️  No se pudo escribir JSON en {}: {}", path, e);
                } else {
                    println!("✅ Reporte JSON escrito en: {}", path);
                }
            }

            // Salida HUMANA por defecto (como la que ya usas)
            print_human_tcp_health(&report, args.top);

            println!("\n--- ANÁLISIS COMPLETADO ---");
        }
        Err(e) => {
            eprintln!("\n--- ERROR ---");
            eprintln!("No se pudo procesar el archivo: {}", e);
        }
    }
}

fn print_human_tcp_health(report: &Value, top_n: usize) {
    // Encabezado parecido a tu salida actual
    println!("\n--- Reporte del Detector de Salud TCP ---");

    let tcp = &report["detectors"]["tcp_health"];
    let convs = tcp["conversations_total"].as_u64().unwrap_or(0);
    println!("Se encontraron {} conversaciones TCP distintas.", convs);

    // Top N (ajustable)
    println!("\nTop {} conversaciones por volumen de paquetes:", top_n);
    if let Some(arr) = tcp["top_flows"].as_array() {
        for entry in arr.iter().take(top_n) {
            let flow = entry["flow"].as_str().unwrap_or("");
            let c2s = &entry["c2s"];
            let s2c = &entry["s2c"];

            println!("  - Flujo: {}", flow);
            println!(
                "    -> C->S: Paquetes: {}, Retrans.: {}, Fuera de Orden: {}, Ventana0: {}, ACKs Dup. (eventos≥3): {}",
                c2s["packets"], c2s["retransmissions"], c2s["out_of_order"], c2s["zero_window_events"], c2s["duplicate_ack_events"]
            );
            println!(
                "    <- S->C: Paquetes: {}, Retrans.: {}, Fuera de Orden: {}, Ventana0: {}, ACKs Dup. (eventos≥3): {}",
                s2c["packets"], s2c["retransmissions"], s2c["out_of_order"], s2c["zero_window_events"], s2c["duplicate_ack_events"]
            );
        }
    }
}
