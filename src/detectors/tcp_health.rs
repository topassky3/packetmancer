// src/detectors/tcp_health.rs

use crate::network::flow::Flow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use etherparse::{SlicedPacket, InternetSlice, TransportSlice};

#[derive(Default, Debug)]
pub struct TcpStreamState {
    pub packet_count: u32,
    pub retransmission_count: u32,
    pub duplicate_ack_count: u32,
    pub out_of_order_count: u32,
    pub seen_sequence_numbers: HashSet<u32>,
    pub highest_seq_seen: Option<u32>,
    // --- CORRECCIÓN: Añadimos '_' para silenciar la advertencia de código no usado ---
    // El compilador nos avisó que este campo no se leía. Al añadir '_', le decimos
    // que es intencional por ahora. Lo usaremos en el futuro.
    pub _last_ack_seen: Option<u32>,
    pub duplicate_ack_events: u32,
}

#[derive(Debug)]
pub struct TcpConversationState {
    pub flow: Flow,
    pub client_to_server: TcpStreamState,
    pub server_to_client: TcpStreamState,
}

impl Default for TcpConversationState {
    fn default() -> Self {
        TcpConversationState {
            flow: Flow {
                source_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                source_port: 0,
                destination_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                destination_port: 0,
            },
            client_to_server: TcpStreamState::default(),
            server_to_client: TcpStreamState::default(),
        }
    }
}

#[derive(Default)]
pub struct TcpHealthDetector {
    conversations: HashMap<Flow, TcpConversationState>,
}

impl TcpHealthDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_packet<'a>(&mut self, packet_data: &'a [u8]) {
        if let Ok(sliced_packet) = SlicedPacket::from_ethernet(packet_data) {
            if let (Some(InternetSlice::Ipv4(ipv4_slice)), Some(TransportSlice::Tcp(tcp_header))) = (sliced_packet.net, sliced_packet.transport) {
                
                let ipv4_header = ipv4_slice.header();
                let current_flow = Flow {
                    source_ip: IpAddr::V4(Ipv4Addr::from(ipv4_header.source())),
                    source_port: tcp_header.source_port(),
                    destination_ip: IpAddr::V4(Ipv4Addr::from(ipv4_header.destination())),
                    destination_port: tcp_header.destination_port(),
                };

                let reverse_flow = current_flow.reverse();
                let conversation = if self.conversations.contains_key(&current_flow) {
                    self.conversations.get_mut(&current_flow).unwrap()
                } else if self.conversations.contains_key(&reverse_flow) {
                    self.conversations.get_mut(&reverse_flow).unwrap()
                } else {
                    let entry = self.conversations.entry(current_flow).or_default();
                    entry.flow = current_flow;
                    entry
                };

                let stream_state = if current_flow == conversation.flow {
                    &mut conversation.client_to_server
                } else {
                    &mut conversation.server_to_client
                };

                stream_state.packet_count += 1;
                
                let seq_num = tcp_header.sequence_number();
                // --- CORRECCIÓN: Añadimos '_' para silenciar la advertencia de variable no usada ---
                let _ack_num = tcp_header.acknowledgment_number();
                let payload_len = tcp_header.payload().len() as u32;

                if stream_state.seen_sequence_numbers.contains(&seq_num) && payload_len > 0 && !tcp_header.syn() && !tcp_header.fin() {
                    stream_state.retransmission_count += 1;
                }
                stream_state.seen_sequence_numbers.insert(seq_num);

                if payload_len > 0 {
                    if let Some(highest_seq) = stream_state.highest_seq_seen {
                        if seq_num < highest_seq {
                            stream_state.duplicate_ack_count += 1;
                        } else if seq_num > highest_seq + 1 {
                            stream_state.out_of_order_count += 1;
                            stream_state.highest_seq_seen = Some(seq_num + payload_len);
                        } else {
                            stream_state.highest_seq_seen = Some(seq_num + payload_len);
                        }
                    } else {
                        stream_state.highest_seq_seen = Some(seq_num + payload_len);
                    }
                }
            }
        }
    }

    pub fn report(&self) {
        println!("\n--- Reporte del Detector de Salud TCP ---");
        println!("Se encontraron {} conversaciones TCP distintas.", self.conversations.len());

        let mut sorted_convs: Vec<_> = self.conversations.values().collect();
        sorted_convs.sort_by_key(|&state| std::cmp::Reverse(state.client_to_server.packet_count + state.server_to_client.packet_count));
        
        println!("\nTop 5 conversaciones por volumen de paquetes:");
        for state in sorted_convs.iter().take(5) {
            let flow = state.flow;
            let c2s = &state.client_to_server;
            let s2c = &state.server_to_client;

            println!("  - Flujo: {}:{} <-> {}:{}", flow.source_ip, flow.source_port, flow.destination_ip, flow.destination_port);
            println!("    -> C->S: Paquetes: {}, Retrans.: {}, Pkts. Dup.: {}, Fuera de Orden: {}, ACKs Dup.: {}", c2s.packet_count, c2s.retransmission_count, c2s.duplicate_ack_count, c2s.out_of_order_count, c2s.duplicate_ack_events);
            println!("    <- S->C: Paquetes: {}, Retrans.: {}, Pkts. Dup.: {}, Fuera de Orden: {}, ACKs Dup.: {}", s2c.packet_count, s2c.retransmission_count, s2c.duplicate_ack_count, s2c.out_of_order_count, s2c.duplicate_ack_events);
        }
    }
}