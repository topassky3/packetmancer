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

    // Heurísticas
    pub seen_seq_numbers: HashSet<u32>, // retransmisión si repite seq con payload
    pub highest_seq_end: Option<u32>,   // mayor (seq + len) observado

    // DupACK
    pub last_ack_seen: Option<u32>,
    pub dup_ack_streak: u32,
    pub duplicate_ack_events: u32, // evento al llegar a 3 ACKs duplicados consecutivos
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

// ----- Scoring de severidad (extraído para test) -----
fn compute_severity(
    c2s: &TcpStreamState,
    s2c: &TcpStreamState,
) -> (u32, &'static str, Vec<String>) {
    let total_pkts = c2s.packet_count.saturating_add(s2c.packet_count);
    let retr = c2s.retransmission_count + s2c.retransmission_count;
    let dup = c2s.duplicate_ack_events + s2c.duplicate_ack_events;
    let zwin = c2s.zero_window_events + s2c.zero_window_events;
    let ooo = c2s.out_of_order_count + s2c.out_of_order_count;

    let ooo_pct = if total_pkts > 0 {
        (ooo as f64) / (total_pkts as f64) * 100.0
    } else {
        0.0
    };

    // Normalización por 1000 paquetes (evita sesgo por flows largos)
    let pkts_k = (total_pkts as f64 / 1000.0).max(1.0);
    let retr_k = retr as f64 / pkts_k; // retrans por 1000 pkts
    let dup_k = dup as f64 / pkts_k; // dupACK events por 1000 pkts
    let zwin_k = zwin as f64 / pkts_k; // zwin por 1000 pkts

    // Ponderación conservadora
    let score_f = 12.0 * retr_k   // retrans pesa mucho
        + 9.0 * zwin_k            // ventana cero muy relevante
        + 4.0 * dup_k             // dupACK pesa menos
        + 2.0 * ooo_pct; // fuera de orden aporta poco

    let mut score = score_f.round() as u32;

    // Razones legibles
    let mut reasons = Vec::<String>::new();
    if retr >= 20 {
        reasons.push(format!("retransmisiones altas ({retr})"));
    } else if retr >= 5 {
        reasons.push(format!("retransmisiones moderadas ({retr})"));
    }

    if zwin >= 1 {
        reasons.push(format!("ventana cero ({zwin})"));
    }

    if dup >= 3 {
        if retr == 0 && zwin == 0 {
            reasons.push(format!("muchos dupACK sin retransmisiones ({dup})"));
        } else {
            reasons.push(format!("eventos de ACK duplicado (≥3) ({dup})"));
        }
    }

    if ooo_pct > 2.0 {
        reasons.push(format!("fuera de orden {ooo_pct:.1}% (~{ooo})"));
    }

    // Gating: no subir a ALTA si no hay señales “fuertes”
    let mut level = if score >= 120 || retr >= 20 || zwin >= 2 {
        "ALTA"
    } else if score >= 50 || retr >= 5 || zwin >= 1 || dup >= 5 || ooo_pct > 2.0 {
        "MEDIA"
    } else {
        "BAJA"
    };

    // Cap adicional: si hay muy pocas retrans y nada de zwin, bajar a MEDIA
    if level == "ALTA" && retr < 3 && zwin == 0 {
        level = "MEDIA";
        if score > 80 {
            score = 80;
        } // reflejar el cap en el score
    }

    (score, level, reasons)
}

impl TcpHealthDetector {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_conv_mut(
        conversations: &mut HashMap<Flow, TcpConversationState>,
        current_flow: Flow,
    ) -> &mut TcpConversationState {
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
        flags: TcpFlags, // <- por valor (Copy)
    ) {
        stream.packet_count += 1;

        // Ventana cero: ACK, sin SYN/RST, win=0
        if flags.ack && !flags.syn && !flags.rst && window_size == 0 {
            stream.zero_window_events += 1;
        }

        // ACKs duplicados (evento al llegar a 3 consecutivos) cuando no hay payload
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

        // Retransmisión: mismo seq con payload (ignorar SYN/FIN)
        if payload_len > 0 && stream.seen_seq_numbers.contains(&seq_num) && !flags.syn && !flags.fin
        {
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

#[derive(Clone, Copy)]
struct TcpFlags {
    syn: bool,
    fin: bool,
    rst: bool,
    ack: bool,
}

impl Detector for TcpHealthDetector {
    fn name(&self) -> &'static str {
        "tcp_health"
    }

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
                let flags = TcpFlags {
                    syn: tcp.syn(),
                    fin: tcp.fin(),
                    rst: tcp.rst(),
                    ack: tcp.ack(),
                };
                let payload_len = tcp.payload().len(); // datos de aplicación

                // Actualiza lado emisor del segmento
                Self::update_stream(fwd, seq, ack, win, payload_len, flags);

                let _ = rev; // reservado para correlaciones futuras
            }
        }
    }

    fn finalize(&mut self) -> Value {
        // ---- construir vistas ----
        let convs: Vec<_> = self.conversations.values().collect();

        // Top por severidad
        let mut by_severity: Vec<Value> = convs
            .iter()
            .map(|st| {
                let (score, level, reasons) = compute_severity(&st.c2s, &st.s2c);

                let src_ip = st.flow.source_ip;
                let src_port = st.flow.source_port;
                let dst_ip = st.flow.destination_ip;
                let dst_port = st.flow.destination_port;
                let flow_str = format!("{src_ip}:{src_port} <-> {dst_ip}:{dst_port}/TCP");

                json!({
                    "flow": flow_str,
                    "score": { "value": score, "level": level },
                    "reasons": reasons,
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
            })
            .collect();

        by_severity.sort_by_key(|v| Reverse(v["score"]["value"].as_u64().unwrap_or(0)));

        // Top por volumen (paquetes)
        let mut by_packets: Vec<&TcpConversationState> = convs.clone();
        by_packets
            .sort_by_key(|st| Reverse(st.c2s.packet_count.saturating_add(st.s2c.packet_count)));
        let by_packets_json: Vec<Value> = by_packets
            .into_iter()
            .map(|st| {
                let src_ip = st.flow.source_ip;
                let src_port = st.flow.source_port;
                let dst_ip = st.flow.destination_ip;
                let dst_port = st.flow.destination_port;
                let flow_str = format!("{src_ip}:{src_port} <-> {dst_ip}:{dst_port}/TCP");

                json!({
                    "flow": flow_str,
                    "total_packets": st.c2s.packet_count.saturating_add(st.s2c.packet_count),
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
            })
            .collect();

        json!({
            "conversations_total": self.conversations.len(),
            "top_by_severity": by_severity,
            "top_by_packets": by_packets_json,
            // alias por compatibilidad
            "top_flows": by_severity
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f_ack() -> TcpFlags {
        TcpFlags {
            syn: false,
            fin: false,
            rst: false,
            ack: true,
        }
    }

    #[test]
    fn dup_ack_event_on_three_consecutive() {
        let mut s = TcpStreamState::default();
        TcpHealthDetector::update_stream(&mut s, 1000, 5000, 1024, 0, f_ack());
        TcpHealthDetector::update_stream(&mut s, 1001, 5000, 1024, 0, f_ack());
        TcpHealthDetector::update_stream(&mut s, 1002, 5000, 1024, 0, f_ack()); // evento
        assert_eq!(s.duplicate_ack_events, 1);
        // streak se resetea si llega payload o cambia ACK
        TcpHealthDetector::update_stream(&mut s, 1003, 5001, 1024, 0, f_ack());
        assert_eq!(s.dup_ack_streak, 1);
    }

    #[test]
    fn retransmission_on_same_seq_with_payload() {
        let mut s = TcpStreamState::default();
        let f = f_ack();
        TcpHealthDetector::update_stream(&mut s, 1000, 0, 1024, 100, f);
        TcpHealthDetector::update_stream(&mut s, 1000, 0, 1024, 100, f);
        assert_eq!(s.retransmission_count, 1);
    }

    #[test]
    fn zero_window_when_ack_with_zero_window() {
        let mut s = TcpStreamState::default();
        TcpHealthDetector::update_stream(&mut s, 1000, 0, 0, 0, f_ack());
        assert_eq!(s.zero_window_events, 1);
    }

    #[test]
    fn out_of_order_when_seq_before_highest_end() {
        let mut s = TcpStreamState::default();
        let f = f_ack();
        TcpHealthDetector::update_stream(&mut s, 1500, 0, 1024, 500, f); // end=2000
        TcpHealthDetector::update_stream(&mut s, 1600, 0, 1024, 100, f); // 1600<2000 => OOO
        assert_eq!(s.out_of_order_count, 1);
    }

    #[test]
    fn severity_caps_when_only_dupacks() {
        // Muchos dupACK, sin retrans ni zwin => no debe ser ALTA
        let mut c2s = TcpStreamState::default();
        let s2c = TcpStreamState::default();
        let f = f_ack();
        // Genera 2 eventos dupACK (6 ACKs duplicados en total)
        TcpHealthDetector::update_stream(&mut c2s, 1, 5000, 1024, 0, f);
        TcpHealthDetector::update_stream(&mut c2s, 2, 5000, 1024, 0, f);
        TcpHealthDetector::update_stream(&mut c2s, 3, 5000, 1024, 0, f); // evento 1
        TcpHealthDetector::update_stream(&mut c2s, 4, 5000, 1024, 0, f);
        TcpHealthDetector::update_stream(&mut c2s, 5, 5000, 1024, 0, f);
        TcpHealthDetector::update_stream(&mut c2s, 6, 5000, 1024, 0, f); // evento 2
        let (_score, level, _reasons) = compute_severity(&c2s, &s2c);
        assert_ne!(level, "ALTA");
    }
}
