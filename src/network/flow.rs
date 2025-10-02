// src/network/flow.rs
use std::net::{IpAddr, Ipv4Addr}; // <-- agrega Ipv4Addr

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Flow {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
}

impl Flow {
    pub fn reverse(&self) -> Self {
        Flow {
            source_ip: self.destination_ip,
            source_port: self.destination_port,
            destination_ip: self.source_ip,
            destination_port: self.source_port,
        }
    }
}

// <-- agrega esta impl
impl Default for Flow {
    fn default() -> Self {
        Flow {
            source_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            source_port: 0,
            destination_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            destination_port: 0,
        }
    }
}
