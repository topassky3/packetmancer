use crate::engine::Detector;
use crate::network::flow::Flow;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use serde_json::{json, Value};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Default, Debug)]
pub struct TcpStreamState {
    pub packet_count: u32,
    pub retransmission_count: u32,
    pub out_of_order_count: u32,
    pub zero_window_events: u32,

    pub seen_seq_numbers: HashSet<u32>, // retransmisión si repite seq con payload
    pub highest_seq_end: Option<u32>,   // mayor (seq + len) observado

    pub last_ack_seen: Option<u32>,     // para ACKs duplicados
    pub dup_ack_streak: u32,
    pub duplicate_ack_events: u32,      // evento al llegar a 3 ACKs duplicados
}

#[derive(Debug, Default)]
pub struct TcpConversationState {
    pub flow: Flow, // dirección canónica
    pub c2s: TcpStreamState,
    pub s2c: TcpStreamState,
}

#[derive(Default)]
pub struct TcpHealthDetector {
    conversations: HashMap<Flow, TcpConversationState>,
}

impl TcpHealthDetector {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_conv_mut<'a>(
        conversations: &'a mut HashMap<Flow, TcpConversationState>,
        current_flow: Flow,
    ) -> &'a mut TcpConversationState {
        if conversations.contains_key(&current_flow) {
            return conversations.get_mut(&current_flow).unwrap();
        }
        let reverse = current_flow.reverse();
        if conversations.contains_key(&reverse) {
            return conversations.get_mut(&reverse).unwrap();
        }
        let entry = conversations.entry(current_flow).or_default();
        entry.flow = current_flow;
        entry
    }

    fn update_stream(
        stream: &mut TcpStreamState,
        seq_num: u32,
        ack_num: u32,
        window_size: u16,
        payload_len: usize,
        flags: TcpFlags,
    ) {
        stream.packet_count += 1;

        // Ventana cero
        if flags.ack && !flags.syn && !flags.rst && window_size == 0 {
            stream.zero_window_events += 1;
        }

        // ACKs duplicados (evento al llegar a 3 consecutivos)
        if payload_len == 0 && flags.ack && !flags.syn && !flags.fin && !flags.rst {
            match stream.last_ack_seen {
                Some(last) if last == ack_num => {
                    stream.dup_ack_streak += 1;
                    if stream.dup_ack_streak == 3 {
                        stream.duplicate_ack_events += 1;
                    }
                }
                _ => {
                    stream.last_ack_seen = Some(ack_num);
                    stream.dup_ack_streak = 1;
                }
            }
        } else {
            stream.dup_ack_streak = 0;
        }

        // Retransmisión: mismo seq con payload
        if payload_len > 0 && stream.seen_seq_numbers.contains(&seq_num) && !flags.syn && !flags.fin {
            stream.retransmission_count += 1;
        }
        stream.seen_seq_numbers.insert(seq_num);

        // Fuera de orden: llega un segmento que empieza antes del mayor fin visto
        if payload_len > 0 {
            let seg_end = seq_num.wrapping_add(payload_len as u32);
            match stream.highest_seq_end {
                Some(max_end) => {
                    if seq_num < max_end {
                        stream.out_of_order_count += 1;
                    }
                    if seg_end > max_end {
                        stream.highest_seq_end = Some(seg_end);
                    }
                }
                None => stream.highest_seq_end = Some(seg_end),
            }
        }
    }
}

struct TcpFlags { syn: bool, fin: bool, rst: bool, ack: bool }

impl Detector for TcpHealthDetector {
    fn name(&self) -> &'static str { "tcp_health" }

    fn on_packet(&mut self, packet_data: &[u8]) {
        if let Ok(sliced) = SlicedPacket::from_ethernet(packet_data) {
            if let (Some(InternetSlice::Ipv4(ip)), Some(TransportSlice::Tcp(tcp))) =
                (sliced.net, sliced.transport)
            {
                let h = ip.header();
                let flow = Flow {
                    source_ip: IpAddr::V4(Ipv4Addr::from(h.source())),
                    source_port: tcp.source_port(),
                    destination_ip: IpAddr::V4(Ipv4Addr::from(h.destination())),
                    destination_port: tcp.destination_port(),
                };

                let conv = Self::get_conv_mut(&mut self.conversations, flow);

                let (fwd, rev) = if flow == conv.flow {
                    (&mut conv.c2s, &mut conv.s2c)
                } else {
                    (&mut conv.s2c, &mut conv.c2s)
                };

                let seq = tcp.sequence_number();
                let ack = tcp.acknowledgment_number();
                let win = tcp.window_size();
                let flags = TcpFlags { syn: tcp.syn(), fin: tcp.fin(), rst: tcp.rst(), ack: tcp.ack() };
                let payload_len = tcp.payload().len();// <- datos de aplicación en este segmento

                // Actualiza lado emisor del segmento
                Self::update_stream(fwd, seq, ack, win, payload_len, flags);

                let _ = rev; // reservado si cruzas señales a futuro
            }
        }
    }

    fn finalize(&mut self) -> Value {
        let mut convs: Vec<_> = self.conversations.values().collect();
        convs.sort_by_key(|st| Reverse(st.c2s.packet_count.saturating_add(st.s2c.packet_count)));

        let top = convs.iter().take(5).map(|st| {
            json!({
                "flow": format!("{}:{} <-> {}:{}/TCP",
                    st.flow.source_ip, st.flow.source_port, st.flow.destination_ip, st.flow.destination_port),
                "c2s": {
                    "packets": st.c2s.packet_count,
                    "retransmissions": st.c2s.retransmission_count,
                    "out_of_order": st.c2s.out_of_order_count,
                    "zero_window_events": st.c2s.zero_window_events,
                    "duplicate_ack_events": st.c2s.duplicate_ack_events
                },
                "s2c": {
                    "packets": st.s2c.packet_count,
                    "retransmissions": st.s2c.retransmission_count,
                    "out_of_order": st.s2c.out_of_order_count,
                    "zero_window_events": st.s2c.zero_window_events,
                    "duplicate_ack_events": st.s2c.duplicate_ack_events
                }
            })
        }).collect::<Vec<_>>();

        json!({
            "conversations_total": self.conversations.len(),
            "top_flows": top
        })
    }
}
