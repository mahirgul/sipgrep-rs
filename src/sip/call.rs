//! SIP Dialog and Call Tracker
//! Groups packets by Call-ID and generates call flow ladder diagrams.

use std::fmt;
use std::net::SocketAddr;
use chrono::{DateTime, Duration, Local};
use crate::sip::parser::{SipMessage, SipMethod, SipType};

/// Endpoint of a SIP transaction
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallEndpoint {
    pub addr: SocketAddr,
    pub alias: Option<String>,
}

impl CallEndpoint {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr, alias: None }
    }
}

impl fmt::Display for CallEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(alias) = &self.alias {
            write!(f, "{alias} ({})", self.addr)
        } else {
            write!(f, "{}", self.addr)
        }
    }
}

/// Call status based on SIP RFC 3261 dialog state machine
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallState {
    Setup,
    Trying,
    Ringing,
    Established,
    Terminated,
    Rejected,
    Cancelled,
    Register,
    Registered,
    Options,
    Message,
    Other(String),
}

impl CallState {
    pub fn label(&self) -> &str {
        match self {
            CallState::Setup => "SETUP",
            CallState::Trying => "TRYING",
            CallState::Ringing => "RINGING",
            CallState::Established => "CALL ESTABLISHED",
            CallState::Terminated => "COMPLETED",
            CallState::Rejected => "REJECTED",
            CallState::Cancelled => "CANCELLED",
            CallState::Register => "REGISTERING",
            CallState::Registered => "REGISTERED",
            CallState::Options => "OPTIONS",
            CallState::Message => "MESSAGE",
            CallState::Other(s) => s.as_str(),
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            CallState::Established | CallState::Registered => "green",
            CallState::Ringing | CallState::Trying => "yellow",
            CallState::Rejected => "red",
            CallState::Cancelled | CallState::Terminated => "gray",
            _ => "cyan",
        }
    }
}

/// Captured packet with network metadata and parsed SIP message
#[derive(Debug, Clone)]
pub struct CallPacket {
    pub packet_num: usize,
    pub timestamp: DateTime<Local>,
    pub src: CallEndpoint,
    pub dst: CallEndpoint,
    pub transport: String,
    pub message: SipMessage,
}

impl CallPacket {
    pub fn summary(&self) -> String {
        self.message.summary_label()
    }
}

/// Ladder diagram step representing a message exchanged between endpoints
#[derive(Debug, Clone)]
pub struct LadderStep {
    pub packet_num: usize,
    pub timestamp: DateTime<Local>,
    pub src_idx: usize,
    pub dst_idx: usize,
    pub label: String,
    pub status_code: Option<u16>,
    pub is_request: bool,
    pub summary: String,
}

/// Full Call / Dialog data structure
#[derive(Debug, Clone)]
pub struct Call {
    pub call_id: String,
    pub initial_method: String,
    pub caller: String,
    pub callee: String,
    pub start_time: DateTime<Local>,
    pub last_time: DateTime<Local>,
    pub state: CallState,
    pub endpoints: Vec<CallEndpoint>,
    pub packets: Vec<CallPacket>,
}

impl Call {
    pub fn new(call_id: String, initial_packet: CallPacket) -> Self {
        let caller = initial_packet
            .message
            .from()
            .map(SipMessage::clean_uri)
            .unwrap_or_else(|| "Unknown".to_string());
        let callee = initial_packet
            .message
            .to()
            .map(SipMessage::clean_uri)
            .unwrap_or_else(|| "Unknown".to_string());

        let initial_method = initial_packet
            .message
            .cseq_method()
            .unwrap_or_else(|| initial_packet.message.summary_label());

        let mut endpoints = Vec::new();
        endpoints.push(initial_packet.src.clone());
        if !endpoints.contains(&initial_packet.dst) {
            endpoints.push(initial_packet.dst.clone());
        }

        let start_time = initial_packet.timestamp;
        let last_time = initial_packet.timestamp;

        let mut call = Self {
            call_id,
            initial_method,
            caller,
            callee,
            start_time,
            last_time,
            state: CallState::Setup,
            endpoints,
            packets: Vec::new(),
        };

        call.add_packet(initial_packet);
        call
    }

    pub fn add_packet(&mut self, packet: CallPacket) {
        self.last_time = packet.timestamp;

        // Register endpoints
        if !self.endpoints.contains(&packet.src) {
            self.endpoints.push(packet.src.clone());
        }
        if !self.endpoints.contains(&packet.dst) {
            self.endpoints.push(packet.dst.clone());
        }

        // Update call state based on RFC 3261 state progression
        match &packet.message.msg_type {
            SipType::Request(req) => match req.method {
                SipMethod::Invite => {
                    if self.state == CallState::Setup || self.state == CallState::Terminated {
                        self.state = CallState::Setup;
                    }
                }
                SipMethod::Ack => {
                    if self.state == CallState::Setup || self.state == CallState::Ringing {
                        self.state = CallState::Established;
                    }
                }
                SipMethod::Bye => {
                    self.state = CallState::Terminated;
                }
                SipMethod::Cancel => {
                    self.state = CallState::Cancelled;
                }
                SipMethod::Register => {
                    self.state = CallState::Register;
                }
                SipMethod::Options => {
                    self.state = CallState::Options;
                }
                SipMethod::Message => {
                    self.state = CallState::Message;
                }
                _ => {}
            },
            SipType::Response(resp) => {
                match resp.status_code {
                    100 => {
                        if self.state == CallState::Setup {
                            self.state = CallState::Trying;
                        }
                    }
                    180 | 183 => {
                        self.state = CallState::Ringing;
                    }
                    200 => {
                        if let Some(cseq_method) = packet.message.cseq_method() {
                            if cseq_method == "INVITE" {
                                self.state = CallState::Established;
                            } else if cseq_method == "REGISTER" {
                                self.state = CallState::Registered;
                            } else if cseq_method == "BYE" {
                                self.state = CallState::Terminated;
                            }
                        }
                    }
                    400..=699 => {
                        if self.state != CallState::Terminated {
                            self.state = CallState::Rejected;
                        }
                    }
                    _ => {}
                }
            }
        }

        self.packets.push(packet);
    }

    pub fn duration(&self) -> Duration {
        self.last_time - self.start_time
    }

    pub fn duration_str(&self) -> String {
        let dur = self.duration();
        let total_secs = dur.num_seconds();
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        let millis = dur.num_milliseconds() % 1000;
        if mins > 0 {
            format!("{mins:02}:{secs:02}.{millis:03}")
        } else {
            format!("{secs:02}.{millis:03}s")
        }
    }

    /// Generate ladder steps for visual flow rendering
    pub fn ladder_steps(&self) -> Vec<LadderStep> {
        let mut steps = Vec::new();

        for pkt in &self.packets {
            let src_idx = self
                .endpoints
                .iter()
                .position(|ep| ep == &pkt.src)
                .unwrap_or(0);
            let dst_idx = self
                .endpoints
                .iter()
                .position(|ep| ep == &pkt.dst)
                .unwrap_or(1.min(self.endpoints.len().saturating_sub(1)));

            let (label, status_code, is_request) = match &pkt.message.msg_type {
                SipType::Request(req) => (req.method.as_str().to_string(), None, true),
                SipType::Response(resp) => (
                    format!("{} {}", resp.status_code, resp.reason),
                    Some(resp.status_code),
                    false,
                ),
            };

            steps.push(LadderStep {
                packet_num: pkt.packet_num,
                timestamp: pkt.timestamp,
                src_idx,
                dst_idx,
                label,
                status_code,
                is_request,
                summary: pkt.summary(),
            });
        }

        steps
    }
}

/// In-memory storage for active and completed calls
#[derive(Debug, Default)]
pub struct CallManager {
    calls: Vec<Call>,
}

impl CallManager {
    pub fn new() -> Self {
        Self { calls: Vec::new() }
    }

    /// Add a captured packet to the corresponding Call by Call-ID
    pub fn handle_packet(&mut self, packet: CallPacket) {
        let call_id = packet
            .message
            .call_id()
            .unwrap_or("no-call-id")
            .to_string();

        if let Some(existing) = self.calls.iter_mut().find(|c| c.call_id == call_id) {
            existing.add_packet(packet);
        } else {
            let new_call = Call::new(call_id, packet);
            self.calls.push(new_call);
        }
    }

    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    pub fn calls_mut(&mut self) -> &mut [Call] {
        &mut self.calls
    }

    pub fn get_call(&self, index: usize) -> Option<&Call> {
        self.calls.get(index)
    }

    pub fn clear(&mut self) {
        self.calls.clear();
    }

    pub fn total_messages(&self) -> usize {
        self.calls.iter().map(|c| c.packets.len()).sum()
    }

    /// Filters calls matching text query (case-insensitive in Call-ID, Caller, Callee, or Method)
    pub fn filter_calls<'a>(&'a self, filter: &str) -> Vec<(usize, &'a Call)> {
        let q = filter.trim().to_lowercase();
        if q.is_empty() {
            return self.calls.iter().enumerate().collect();
        }

        self.calls
            .iter()
            .enumerate()
            .filter(|(_, call)| {
                call.call_id.to_lowercase().contains(&q)
                    || call.caller.to_lowercase().contains(&q)
                    || call.callee.to_lowercase().contains(&q)
                    || call.initial_method.to_lowercase().contains(&q)
                    || call.state.label().to_lowercase().contains(&q)
                    || call
                        .endpoints
                        .iter()
                        .any(|ep| ep.addr.to_string().contains(&q))
            })
            .collect()
    }
}
