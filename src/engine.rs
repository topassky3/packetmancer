use pcap::Capture;
use serde_json::{json, Value};
use std::path::Path;

/// Interfaz común Detector: init→on_packet→finalize (JSON)
pub trait Detector {
    fn name(&self) -> &'static str;
    fn on_packet(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Value;
}

pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Engine {
    pub fn new() -> Self {
        Self { detectors: Vec::new() }
    }

    pub fn register<D: Detector + 'static>(&mut self, detector: D) {
        self.detectors.push(Box::new(detector));
    }

    /// Procesa el PCAP en streaming y devuelve un JSON {summary, detectors}
    pub fn run(&mut self, file_path: &str) -> Result<Value, String> {
        let p = Path::new(file_path);
        if !p.exists() {
            return Err(format!("El archivo no existe: {}", file_path));
        }

        let mut cap = Capture::from_file(p)
            .map_err(|e| format!("Error al abrir la captura: {}", e))?;

        let mut packets_total: u64 = 0;

        while let Ok(pkt) = cap.next_packet() {
            packets_total += 1;
            for d in self.detectors.iter_mut() {
                d.on_packet(pkt.data);
            }
        }

        // Recoger resultados de cada detector
        let mut det_map = serde_json::Map::new();
        for d in self.detectors.iter_mut() {
            det_map.insert(d.name().to_string(), d.finalize());
        }

        Ok(json!({
            "summary": {
                "file": file_path,
                "packets_total": packets_total
            },
            "detectors": det_map
        }))
    }
}
