// src/network/flow.rs

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Flow {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
}

impl Flow {
    /// Devuelve un nuevo Flow con la dirección invertida (fuente <-> destino).
    pub fn reverse(&self) -> Self {
        Flow {
            source_ip: self.destination_ip,
            source_port: self.destination_port,
            destination_ip: self.source_ip,
            destination_port: self.source_port,
        }
    }
}