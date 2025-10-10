use crate::engine::Detector;
use crate::network::flow::Flow;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use serde_json::{json, Value};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Default, Debug)]
pub struct TcpStreamState {
    // Métricas base
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

    // RTT (campos internos; no exponer tipos privados)
    outstanding: VecDeque<OutstandingSegment>, // segmentos enviados pendientes de ACK
    rtt: RttStats,                             // stats de RTT en µs (cap de muestras)
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

// ---- RTT support ----

#[derive(Clone, Copy, Debug)]
struct OutstandingSegment {
    seq_end: u32, // sequence_number + payload_len
    ts_us: u64,   // timestamp de envío (µs)
}

#[derive(Debug, Default)]
struct RttStats {
    samples: Vec<u64>, // µs (cap)
    count: u64,
    min_us: Option<u64>,
    max_us: Option<u64>,
}

impl RttStats {
    const CAP: usize = 4096;

    fn add_sample(&mut self, us: u64) {
        self.count = self.count.saturating_add(1);
        if self.samples.len() < Self::CAP {
            self.samples.push(us);
        }
        self.min_us = Some(self.min_us.map_or(us, |m| m.min(us)));
        self.max_us = Some(self.max_us.map_or(us, |m| m.max(us)));
    }

    fn percentiles_ms(&self) -> (f64, f64) {
        if self.samples.is_empty() {
            return (0.0, 0.0);
        }
        let mut v = self.samples.clone();
        v.sort_unstable();
        let p50 = quantile_us(&v, 0.50) as f64 / 1000.0;
        let p95 = quantile_us(&v, 0.95) as f64 / 1000.0;
        (p50, p95)
    }
}

fn quantile_us(sorted_us: &[u64], q: f64) -> u64 {
    if sorted_us.is_empty() {
        return 0;
    }
    let n = sorted_us.len();
    let pos = ((n - 1) as f64 * q).round() as usize;
    sorted_us[pos]
}

// Comparación modular de secuencias TCP (a <= b)
#[inline]
fn seq_lte(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) as i32 >= 0
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

    #[inline]
    fn on_data(
        stream: &mut TcpStreamState,
        seq_num: u32,
        payload_len: usize,
        flags: TcpFlags,
        ts_us: u64,
    ) {
        // Retransmisión (mismo seq con payload; ignora SYN/FIN)
        if payload_len > 0 && stream.seen_seq_numbers.contains(&seq_num) && !flags.syn && !flags.fin
        {
            stream.retransmission_count += 1;
        }
        stream.seen_seq_numbers.insert(seq_num);

        // OOO vs highest end
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

            // Registrar pendiente para RTT
            stream.outstanding.push_back(OutstandingSegment {
                seq_end: seg_end,
                ts_us,
            });
        }
    }

    #[inline]
    fn on_ack(sender_stream: &mut TcpStreamState, ack_num: u32, ts_us: u64) {
        // Consumir todos los segmentos confirmados por ACK acumulativo
        while let Some(front) = sender_stream.outstanding.front().copied() {
            if seq_lte(front.seq_end, ack_num) {
                let rtt = ts_us.saturating_sub(front.ts_us);
                sender_stream.rtt.add_sample(rtt);
                sender_stream.outstanding.pop_front();
            } else {
                break;
            }
        }
    }

    fn update_stream(
        stream: &mut TcpStreamState,
        seq_num: u32,
        ack_num: u32,
        window_size: u16,
        payload_len: usize,
        flags: TcpFlags, // por valor (Copy)
        ts_us: u64,
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

        // DATA path (incluye heurísticas y registrar outstanding)
        Self::on_data(stream, seq_num, payload_len, flags, ts_us);
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

    fn on_packet(&mut self, packet_data: &[u8], ts_micros: u64) {
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

                // Actualiza lado emisor del segmento (métricas + outstanding)
                Self::update_stream(fwd, seq, ack, win, payload_len, flags, ts_micros);

                // **ACK piggyback**: usa cualquier ACK válido (con o sin payload) para RTT
                if flags.ack && !flags.syn && !flags.fin && !flags.rst {
                    Self::on_ack(rev, ack, ts_micros);
                }
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

                // RTT percentiles (en ms)
                let (c2s_p50, c2s_p95) = st.c2s.rtt.percentiles_ms();
                let (s2c_p50, s2c_p95) = st.s2c.rtt.percentiles_ms();

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
                        "duplicate_ack_events": st.c2s.duplicate_ack_events,
                        "rtt_ms": {
                            "p50": c2s_p50,
                            "p95": c2s_p95,
                            "samples": st.c2s.rtt.count
                        }
                    },
                    "s2c": {
                        "packets": st.s2c.packet_count,
                        "retransmissions": st.s2c.retransmission_count,
                        "out_of_order": st.s2c.out_of_order_count,
                        "zero_window_events": st.s2c.zero_window_events,
                        "duplicate_ack_events": st.s2c.duplicate_ack_events,
                        "rtt_ms": {
                            "p50": s2c_p50,
                            "p95": s2c_p95,
                            "samples": st.s2c.rtt.count
                        }
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
                let (c2s_p50, c2s_p95) = st.c2s.rtt.percentiles_ms();
                let (s2c_p50, s2c_p95) = st.s2c.rtt.percentiles_ms();

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
                        "duplicate_ack_events": st.c2s.duplicate_ack_events,
                        "rtt_ms": { "p50": c2s_p50, "p95": c2s_p95, "samples": st.c2s.rtt.count }
                    },
                    "s2c": {
                        "packets": st.s2c.packet_count,
                        "retransmissions": st.s2c.retransmission_count,
                        "out_of_order": st.s2c.out_of_order_count,
                        "zero_window_events": st.s2c.zero_window_events,
                        "duplicate_ack_events": st.s2c.duplicate_ack_events,
                        "rtt_ms": { "p50": s2c_p50, "p95": s2c_p95, "samples": st.s2c.rtt.count }
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
        TcpHealthDetector::update_stream(&mut s, 1000, 5000, 1024, 0, f_ack(), 10);
        TcpHealthDetector::update_stream(&mut s, 1001, 5000, 1024, 0, f_ack(), 20);
        TcpHealthDetector::update_stream(&mut s, 1002, 5000, 1024, 0, f_ack(), 30); // evento
        assert_eq!(s.duplicate_ack_events, 1);
        // streak se resetea si cambia ACK
        TcpHealthDetector::update_stream(&mut s, 1003, 5001, 1024, 0, f_ack(), 40);
        assert_eq!(s.dup_ack_streak, 1);
    }

    #[test]
    fn retransmission_on_same_seq_with_payload() {
        let mut s = TcpStreamState::default();
        let f = f_ack();
        TcpHealthDetector::update_stream(&mut s, 1000, 0, 1024, 100, f, 0);
        TcpHealthDetector::update_stream(&mut s, 1000, 0, 1024, 100, f, 10);
        assert_eq!(s.retransmission_count, 1);
    }

    #[test]
    fn zero_window_when_ack_with_zero_window() {
        let mut s = TcpStreamState::default();
        TcpHealthDetector::update_stream(&mut s, 1000, 0, 0, 0, f_ack(), 0);
        assert_eq!(s.zero_window_events, 1);
    }

    #[test]
    fn out_of_order_when_seq_before_highest_end() {
        let mut s = TcpStreamState::default();
        let f = f_ack();
        TcpHealthDetector::update_stream(&mut s, 1500, 0, 1024, 500, f, 0); // end=2000
        TcpHealthDetector::update_stream(&mut s, 1600, 0, 1024, 100, f, 1); // 1600<2000 => OOO
        assert_eq!(s.out_of_order_count, 1);
    }

    #[test]
    fn severity_caps_when_only_dupacks() {
        // Muchos dupACK, sin retrans ni zwin => no debe ser ALTA
        let mut c2s = TcpStreamState::default();
        let s2c = TcpStreamState::default();
        let f = f_ack();
        // Genera 2 eventos dupACK (6 ACKs duplicados en total)
        TcpHealthDetector::update_stream(&mut c2s, 1, 5000, 1024, 0, f, 0);
        TcpHealthDetector::update_stream(&mut c2s, 2, 5000, 1024, 0, f, 1);
        TcpHealthDetector::update_stream(&mut c2s, 3, 5000, 1024, 0, f, 2); // evento 1
        TcpHealthDetector::update_stream(&mut c2s, 4, 5000, 1024, 0, f, 3);
        TcpHealthDetector::update_stream(&mut c2s, 5, 5000, 1024, 0, f, 4);
        TcpHealthDetector::update_stream(&mut c2s, 6, 5000, 1024, 0, f, 5); // evento 2
        let (_score, level, _reasons) = super::compute_severity(&c2s, &s2c);
        assert_ne!(level, "ALTA");
    }

    #[test]
    fn rtt_is_measured_on_ack_of_data() {
        // Simula DATA C->S seguido de ACK S->C
        let mut conv = TcpConversationState::default();
        let c2s = &mut conv.c2s;
        let s2c = &mut conv.s2c;

        // DATA C->S: seq=1000, len=100 => end=1100, ts=1_000_000us
        TcpHealthDetector::update_stream(c2s, 1000, 0, 65535, 100, f_ack(), 1_000_000);

        // ACK S->C: ack=1100, ts=1_120_000us  => RTT ~120ms
        TcpHealthDetector::on_ack(c2s, 1100, 1_120_000);

        let (p50, p95) = c2s.rtt.percentiles_ms();
        assert!(p50 >= 119.0 && p50 <= 121.0, "p50={p50}");
        assert!(p95 >= 119.0 && p95 <= 121.0, "p95={p95}");
        assert_eq!(c2s.rtt.count, 1);
        assert!(s2c.rtt.count == 0);
    }
}
