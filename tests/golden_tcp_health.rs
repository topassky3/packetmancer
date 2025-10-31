// tests/golden_tcp_health.rs
use packetmancer::{Engine, TcpHealthDetector};
use serde_json::Value;
use std::path::Path;

fn run_engine(path: &str) -> Value {
    let mut eng = Engine::new();
    eng.register(TcpHealthDetector::new());
    eng.run(path).expect("engine run failed")
}

#[test]
fn deterministic_same_input_same_json() {
    // mismo input => mismo JSON (verifica orden estable de nuestro pipeline)
    let pcap = "tests/fixtures/tiny.pcap";
    let a = run_engine(pcap);
    let b = run_engine(pcap);
    assert_eq!(a, b, "El JSON no fue determinista con la misma captura");
}

#[test]
fn golden_small_capture() {
    let pcap = "tests/fixtures/tiny.pcap";
    let out = run_engine(pcap);

    let golden_path = "tests/golden/tiny_tcp_health.json";

    // Si pedimos actualizar (o aún no existe), escribimos el golden
    let update = std::env::var("UPDATE_GOLDEN").ok().as_deref() == Some("1");
    let golden_exists = Path::new(golden_path).exists();

    if update || !golden_exists {
        std::fs::create_dir_all("tests/golden").unwrap();
        std::fs::write(golden_path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
        // Si solo estamos generando, marcamos el test como exitoso
        return;
    }

    let golden_str = std::fs::read_to_string(golden_path).expect("missing golden");
    let golden: Value = serde_json::from_str(&golden_str).expect("invalid golden json");

    // 1) Comparación estricta de la sección analítica (detectors)
    assert_eq!(
        out["detectors"], golden["detectors"],
        "Cambió la sección 'detectors' (estructura/valores)."
    );

    // 2) En summary, comparamos solo los campos estables y verificamos tipos del resto
    for k in ["schema", "file", "packets_total", "bytes_total"] {
        assert_eq!(
            out["summary"][k], golden["summary"][k],
            "summary.{k} difiere respecto al golden"
        );
    }

    // Campos derivados del tiempo: pueden variar según cómo midamos duración.
    assert!(
        out["summary"]["duration_ms"].is_number(),
        "summary.duration_ms debe existir y ser numérico"
    );
    assert!(
        out["summary"]["throughput_mbps"].is_number(),
        "summary.throughput_mbps debe existir y ser numérico"
    );
}
