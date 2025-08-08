/* ===================================================================
 * Filename:  src/main.rs
 *
 * Descripción:  Punto de entrada principal de PacketMancer.
 * ===================================================================
 */

use std::path::Path;
use clap::Parser;
use pcap::Capture;

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
        Ok(packet_count) => {
            println!("\n--- ANÁLISIS COMPLETADO ---");
            println!("Se han procesado un total de {} paquetes.", packet_count);
        }
        Err(e) => {
            eprintln!("\n--- ERROR ---");
            eprintln!("No se pudo procesar el archivo: {}", e);
        }
    }
}

/// Esta función utiliza la librería `pcap` para leer el archivo.
fn process_pcap_file(file_path_str: &str) -> Result<u32, String> {
    let path = Path::new(file_path_str);
    if !path.exists() {
        return Err(format!("El archivo no existe en la ruta especificada: {}", file_path_str));
    }

    let mut capture = Capture::from_file(path)
        .map_err(|e| format!("Error al abrir la captura: {}", e))?;

    let mut packet_count = 0;

    while let Ok(_packet) = capture.next_packet() {
        packet_count += 1;
    }

    Ok(packet_count)
}
