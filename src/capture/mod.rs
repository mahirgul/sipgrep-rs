//! Network packet capture engine using libpcap and etherparse.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use anyhow::{Context, Result};
use chrono::{DateTime, Local, TimeZone};
use crossbeam_channel::Sender;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device};

use crate::sip::{CallEndpoint, CallPacket, SipMessage};

/// Configuration for packet capture
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub interface: Option<String>,
    pub pcap_file: Option<String>,
    pub bpf_filter: Option<String>,
    pub port: u16,
    pub buffer_size: i32,
    pub promisc: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: None,
            pcap_file: None,
            bpf_filter: None,
            port: 5060,
            buffer_size: 2 * 1024 * 1024, // 2MB
            promisc: true,
        }
    }
}

/// Spawns background capture thread and sends decoded SIP packets through channel
pub fn start_capture(
    config: CaptureConfig,
    sender: Sender<CallPacket>,
    running: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<()>> {
    let handle = thread::Builder::new()
        .name("sipgrep-capture".into())
        .spawn(move || {
            if let Err(e) = run_capture_loop(config, sender, running) {
                eprintln!("[Capture Error]: {e}");
            }
        })
        .context("Failed to spawn packet capture thread")?;

    Ok(handle)
}

fn run_capture_loop(
    config: CaptureConfig,
    sender: Sender<CallPacket>,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let default_filter = format!("udp port {} or tcp port {}", config.port, config.port);
    let filter = config.bpf_filter.as_deref().unwrap_or(&default_filter);

    let mut packet_num: usize = 0;

    if let Some(file_path) = &config.pcap_file {
        // Offline file mode
        let mut cap = Capture::from_file(file_path)
            .with_context(|| format!("Failed to open PCAP file: {file_path}"))?;

        if !filter.is_empty() {
            let _ = cap.filter(filter, true);
        }

        while running.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    packet_num += 1;
                    let ts = packet_timestamp(&packet);
                    if let Some(call_pkt) = parse_raw_packet(packet_num, ts, packet.data) {
                        if sender.send(call_pkt).is_err() {
                            break;
                        }
                    }
                }
                Err(pcap::Error::NoMorePackets) => {
                    // Reached EOF of pcap file
                    break;
                }
                Err(e) => {
                    eprintln!("Error reading pcap packet: {e}");
                    break;
                }
            }
        }
    } else {
        // Live capture mode
        let device = if let Some(iface) = &config.interface {
            Device::list()?
                .into_iter()
                .find(|d| d.name == *iface)
                .ok_or_else(|| anyhow::anyhow!("Network interface '{iface}' not found"))?
        } else {
            Device::lookup()?
                .ok_or_else(|| anyhow::anyhow!("No default network interface found"))?
        };

        let mut cap = Capture::from_device(device)?
            .promisc(config.promisc)
            .snaplen(65535)
            .buffer_size(config.buffer_size)
            .timeout(500)
            .open()
            .context("Failed to open capture device. Do you have root/CAP_NET_RAW permissions?")?;

        if !filter.is_empty() {
            cap.filter(filter, true)
                .with_context(|| format!("Failed to compile BPF filter '{filter}'"))?;
        }

        while running.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    packet_num += 1;
                    let ts = packet_timestamp(&packet);
                    if let Some(call_pkt) = parse_raw_packet(packet_num, ts, packet.data) {
                        if sender.send(call_pkt).is_err() {
                            break;
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Timeout, continue loop to check running flag
                    continue;
                }
                Err(e) => {
                    if running.load(Ordering::Relaxed) {
                        eprintln!("Capture error: {e}");
                    }
                    break;
                }
            }
        }
    }

    Ok(())
}

fn packet_timestamp(packet: &pcap::Packet) -> DateTime<Local> {
    let sec = packet.header.ts.tv_sec;
    let usec = packet.header.ts.tv_usec;
    Local
        .timestamp_opt(sec, (usec * 1000) as u32)
        .single()
        .unwrap_or_else(Local::now)
}

/// Parses raw ethernet/IP/transport packet, extracts payload, and parses SIP
pub fn parse_raw_packet(packet_num: usize, ts: DateTime<Local>, data: &[u8]) -> Option<CallPacket> {
    // Try ethernet parsing first
    if let Ok(sliced) = SlicedPacket::from_ethernet(data) {
        return extract_sip_from_sliced(packet_num, ts, &sliced);
    }

    // Try raw IP packet parsing (e.g. loopback or Linux cooked capture)
    if let Ok(sliced) = SlicedPacket::from_ip(data) {
        return extract_sip_from_sliced(packet_num, ts, &sliced);
    }

    // Fallback: search directly in payload for SIP signature
    extract_sip_fallback(packet_num, ts, data)
}

fn extract_sip_from_sliced(
    packet_num: usize,
    ts: DateTime<Local>,
    sliced: &SlicedPacket,
) -> Option<CallPacket> {
    let (src_ip, dst_ip) = match &sliced.net {
        Some(NetSlice::Ipv4(ip)) => {
            let h = ip.header();
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
            )
        }
        Some(NetSlice::Ipv6(ip)) => {
            let h = ip.header();
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
            )
        }
        _ => return None,
    };

    let (src_port, dst_port, transport, payload) = match &sliced.transport {
        Some(TransportSlice::Udp(udp)) => (udp.source_port(), udp.destination_port(), "UDP", udp.payload()),
        Some(TransportSlice::Tcp(tcp)) => (tcp.source_port(), tcp.destination_port(), "TCP", tcp.payload()),
        _ => return None,
    };

    if payload.is_empty() {
        return None;
    }

    let sip_msg = SipMessage::parse(payload)?;

    Some(CallPacket {
        packet_num,
        timestamp: ts,
        src: CallEndpoint::new(SocketAddr::new(src_ip, src_port)),
        dst: CallEndpoint::new(SocketAddr::new(dst_ip, dst_port)),
        transport: transport.to_string(),
        message: sip_msg,
    })
}

fn extract_sip_fallback(
    packet_num: usize,
    ts: DateTime<Local>,
    data: &[u8],
) -> Option<CallPacket> {
    // Look for SIP signature like "SIP/2.0", "INVITE ", "REGISTER ", "OPTIONS ", "BYE "
    let text = String::from_utf8_lossy(data);
    let sip_keywords = [
        "INVITE ", "SIP/2.0 ", "REGISTER ", "OPTIONS ", "BYE ", "ACK ", "CANCEL ", "MESSAGE ",
    ];

    if let Some(pos) = sip_keywords.iter().filter_map(|kw| text.find(kw)).min() {
        let payload = &data[pos..];
        let sip_msg = SipMessage::parse(payload)?;

        let dummy_src: SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let dummy_dst: SocketAddr = "127.0.0.1:5060".parse().unwrap();

        Some(CallPacket {
            packet_num,
            timestamp: ts,
            src: CallEndpoint::new(dummy_src),
            dst: CallEndpoint::new(dummy_dst),
            transport: "UDP".to_string(),
            message: sip_msg,
        })
    } else {
        None
    }
}
