use pcap::Capture;
use serde_json::{json, Value};
use std::path::Path;
use std::time::Instant;

pub trait Detector {
    fn name(&self) -> &'static str;

    /// Timestamp del paquete en microsegundos desde epoch (pcap header)
    fn on_packet(&mut self, data: &[u8], ts_micros: u64);

    fn finalize(&mut self) -> Value;
}

pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Engine {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn register<D: Detector + 'static>(&mut self, detector: D) {
        self.detectors.push(Box::new(detector));
    }

    pub fn run(&mut self, file_path: &str) -> Result<Value, String> {
        let p = Path::new(file_path);
        if !p.exists() {
            return Err(format!("El archivo no existe: {file_path}"));
        }

        let file_bytes = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);

        let start = Instant::now();
        let mut cap =
            Capture::from_file(p).map_err(|e| format!("Error al abrir la captura: {e}"))?;

        let mut packets_total: u64 = 0;
        while let Ok(pkt) = cap.next_packet() {
            packets_total += 1;

            // timestamp del paquete (pcap timeval: segundos + microsegundos) SIN unsafe
            let secs = pkt.header.ts.tv_sec as u64;
            let usecs = pkt.header.ts.tv_usec as u64;
            let ts_micros = secs.saturating_mul(1_000_000).saturating_add(usecs);

            for d in self.detectors.iter_mut() {
                d.on_packet(pkt.data, ts_micros);
            }
        }
        let duration_ms = start.elapsed().as_millis() as u64;

        let duration_secs = (duration_ms as f64) / 1000.0;
        let throughput_mbps = if duration_secs > 0.0 {
            (file_bytes as f64 * 8.0) / duration_secs / 1_000_000.0
        } else {
            0.0
        };

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
