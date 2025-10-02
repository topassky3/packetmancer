// src/main.rs

use std::path::Path;
use clap::Parser;
use pcap::Capture;

// Le decimos a Rust que use nuestros nuevos módulos.
mod detectors;
mod network;

// Importamos nuestro nuevo detector.
use detectors::tcp_health::TcpHealthDetector;

#[derive(Parser, Debug)]
#[command(version, about = "PacketMancer - Analizador de Red Inteligente", long_about = None)]
struct Args {
    #[arg(short, long)]
    file: String,
}

fn main() {
    let args = Args::parse();
    println!("Iniciando análisis del archivo: {}", &args.file);

    match process_pcap_file(&args.file) {
        Ok(()) => {
            println!("\n--- ANÁLISIS COMPLETADO ---");
        }
        Err(e) => {
            eprintln!("\n--- ERROR ---");
            eprintln!("No se pudo procesar el archivo: {}", e);
        }
    }
}

/// Esta función ahora orquesta el análisis usando los detectores.
fn process_pcap_file(file_path_str: &str) -> Result<(), String> {
    let path = Path::new(file_path_str);
    if !path.exists() {
        return Err(format!("El archivo no existe en la ruta especificada: {}", file_path_str));
    }

    let mut capture = Capture::from_file(path)
        .map_err(|e| format!("Error al abrir la captura: {}", e))?;

    // 1. Creamos una instancia de nuestro detector.
    let mut tcp_detector = TcpHealthDetector::new();

    // 2. Iteramos sobre cada paquete.
    while let Ok(packet) = capture.next_packet() {
        // 3. Pasamos los datos crudos del paquete a nuestro detector.
        tcp_detector.on_packet(packet.data);
    }

    // 4. Al final, le pedimos al detector que genere su reporte.
    tcp_detector.report();

    Ok(())
}