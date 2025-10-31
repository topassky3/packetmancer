use pcap::Capture;
use serde_json::{json, Value};
use std::path::Path;

pub trait Detector {
    fn name(&self) -> &'static str;

    /// Timestamp del paquete en microsegundos desde epoch (pcap header)
    fn on_packet(&mut self, data: &[u8], ts_micros: u64);

    /// Llamado al final para obtener el reporte del detector
    fn finalize(&mut self) -> Value;
}

#[derive(Default)]
pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Engine {
    /// Crea un Engine vacío (existe `Default`)
    pub fn new() -> Self {
        Self::default()
    }

    /// Registra un detector
    pub fn register<D: Detector + 'static>(&mut self, detector: D) {
        self.detectors.push(Box::new(detector));
    }

    /// Ejecuta el pipeline de análisis sobre un archivo PCAP/PCAPNG
    /// Nota: duración y throughput se calculan de forma determinista a partir de los timestamps del PCAP.
    pub fn run(&mut self, file_path: &str) -> Result<Value, String> {
        let p = Path::new(file_path);
        if !p.exists() {
            return Err(format!("El archivo no existe: {file_path}"));
        }

        let file_bytes = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);

        let mut cap =
            Capture::from_file(p).map_err(|e| format!("Error al abrir la captura: {e}"))?;

        let mut packets_total: u64 = 0;

        // Timestamps deterministas basados en PCAP
        let mut first_ts_us: Option<u64> = None;
        let mut last_ts_us: Option<u64> = None;

        while let Ok(pkt) = cap.next_packet() {
            packets_total += 1;

            // timestamp (pcap timeval: segundos + microsegundos)
            let secs = pkt.header.ts.tv_sec as u64;
            let usecs = pkt.header.ts.tv_usec as u64;
            let ts_micros = secs.saturating_mul(1_000_000).saturating_add(usecs);

            if first_ts_us.is_none() {
                first_ts_us = Some(ts_micros);
            }
            last_ts_us = Some(ts_micros);

            for d in self.detectors.iter_mut() {
                d.on_packet(pkt.data, ts_micros);
            }
        }

        // Duración determinista (en ms) a partir del rango de timestamps del PCAP
        let duration_ms: u64 = match (first_ts_us, last_ts_us) {
            (Some(f), Some(l)) if l >= f => (l - f) / 1_000, // µs -> ms (truncado)
            _ => 0,
        };

        let duration_secs = (duration_ms as f64) / 1000.0;

        // Throughput determinista (si duración == 0 -> 0.0)
        let throughput_mbps = if duration_secs > 0.0 {
            (file_bytes as f64 * 8.0) / duration_secs / 1_000_000.0
        } else {
            0.0
        };

        // Finalizar y recolectar reportes
        let mut det_map = serde_json::Map::new();
        for d in self.detectors.iter_mut() {
            det_map.insert(d.name().to_string(), d.finalize());
        }

        Ok(json!({
            "summary": {
                "schema": "v1",
                "file": file_path,
                "packets_total": packets_total,
                "duration_ms": duration_ms,
                "bytes_total": file_bytes,
                "throughput_mbps": throughput_mbps
            },
            "detectors": det_map
        }))
    }
}
