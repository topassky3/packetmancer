// src/lib.rs
pub mod detectors;
pub mod engine;
pub mod network;

// Re-exports para que el test de integración sea simple
pub use detectors::tcp_health::TcpHealthDetector;
pub use engine::{Detector, Engine};
