//! Clean-room implementation of SIP (Session Initiation Protocol) RFC 3261 message parser.

use std::collections::HashMap;
use std::fmt;

/// Standard SIP Methods defined in RFC 3261 and extensions (RFC 3262, RFC 3265, RFC 3428, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SipMethod {
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    Register,
    Info,
    Prack,
    Subscribe,
    Notify,
    Publish,
    Message,
    Update,
    Refer,
    Other(String),
}

impl SipMethod {
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_uppercase().as_str() {
            "INVITE" => SipMethod::Invite,
            "ACK" => SipMethod::Ack,
            "BYE" => SipMethod::Bye,
            "CANCEL" => SipMethod::Cancel,
            "OPTIONS" => SipMethod::Options,
            "REGISTER" => SipMethod::Register,
            "INFO" => SipMethod::Info,
            "PRACK" => SipMethod::Prack,
            "SUBSCRIBE" => SipMethod::Subscribe,
            "NOTIFY" => SipMethod::Notify,
            "PUBLISH" => SipMethod::Publish,
            "MESSAGE" => SipMethod::Message,
            "UPDATE" => SipMethod::Update,
            "REFER" => SipMethod::Refer,
            other => SipMethod::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            SipMethod::Invite => "INVITE",
            SipMethod::Ack => "ACK",
            SipMethod::Bye => "BYE",
            SipMethod::Cancel => "CANCEL",
            SipMethod::Options => "OPTIONS",
            SipMethod::Register => "REGISTER",
            SipMethod::Info => "INFO",
            SipMethod::Prack => "PRACK",
            SipMethod::Subscribe => "SUBSCRIBE",
            SipMethod::Notify => "NOTIFY",
            SipMethod::Publish => "PUBLISH",
            SipMethod::Message => "MESSAGE",
            SipMethod::Update => "UPDATE",
            SipMethod::Refer => "REFER",
            SipMethod::Other(s) => s.as_str(),
        }
    }
}

impl fmt::Display for SipMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Request Line: Method SP Request-URI SP SIP-Version CRLF
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipRequest {
    pub method: SipMethod,
    pub uri: String,
    pub version: String,
}

/// Status Line: SIP-Version SP Status-Code SP Reason-Phrase CRLF
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
}

/// Type of SIP Message
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipType {
    Request(SipRequest),
    Response(SipResponse),
}

/// Parsed SIP Header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipHeader {
    pub name: String,
    pub value: String,
}

/// Fully parsed SIP Message conforming to RFC 3261
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipMessage {
    pub msg_type: SipType,
    pub headers: Vec<SipHeader>,
    pub header_map: HashMap<String, String>,
    pub body: Vec<u8>,
    pub raw: String,
}

impl SipMessage {
    /// Attempts to parse raw byte slice into a SIP message.
    pub fn parse(raw_bytes: &[u8]) -> Option<Self> {
        let raw_str = String::from_utf8_lossy(raw_bytes);
        Self::parse_str(&raw_str)
    }

    /// Parse SIP message from string slice
    pub fn parse_str(raw_str: &str) -> Option<Self> {
        let trimmed = raw_str.trim_start();
        if trimmed.is_empty() {
            return None;
        }

        // Split into headers part and body part
        let (header_part, body_part) = if let Some(idx) = trimmed.find("\r\n\r\n") {
            (&trimmed[..idx], &trimmed[idx + 4..])
        } else if let Some(idx) = trimmed.find("\n\n") {
            (&trimmed[..idx], &trimmed[idx + 2..])
        } else {
            (trimmed, "")
        };

        let mut lines = header_part.lines();
        let first_line = lines.next()?.trim();
        if first_line.is_empty() {
            return None;
        }

        let msg_type = if first_line.starts_with("SIP/2.0") {
            // Response: SIP/2.0 200 OK
            let mut parts = first_line.splitn(3, ' ');
            let version = parts.next()?.trim().to_string();
            let code_str = parts.next()?.trim();
            let status_code: u16 = code_str.parse().ok()?;
            let reason = parts.next().unwrap_or("").trim().to_string();
            SipType::Response(SipResponse {
                version,
                status_code,
                reason,
            })
        } else {
            // Request: INVITE sip:user@example.com SIP/2.0
            let mut parts = first_line.splitn(3, ' ');
            let method_str = parts.next()?.trim();
            let uri = parts.next()?.trim().to_string();
            let version = parts.next().unwrap_or("SIP/2.0").trim().to_string();

            if !version.starts_with("SIP/") && !uri.contains(':') && !first_line.contains("SIP/2.0") {
                return None;
            }

            SipType::Request(SipRequest {
                method: SipMethod::from_str(method_str),
                uri,
                version,
            })
        };

        let mut headers = Vec::new();
        let mut header_map = HashMap::new();

        // Parse remaining lines handling header folding (RFC 3261 Section 7.3.1)
        let mut current_name: Option<String> = None;
        let mut current_value: Option<String> = None;

        for line in lines {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation line
                if let Some(ref mut val) = current_value {
                    val.push(' ');
                    val.push_str(line.trim());
                }
            } else if let Some(colon_idx) = line.find(':') {
                // Save previous header if any
                if let (Some(name), Some(val)) = (current_name.take(), current_value.take()) {
                    let canon_name = canonicalize_header_name(&name);
                    header_map.insert(canon_name.to_lowercase(), val.clone());
                    headers.push(SipHeader {
                        name: canon_name,
                        value: val,
                    });
                }

                let name = line[..colon_idx].trim().to_string();
                let val = line[colon_idx + 1..].trim().to_string();
                current_name = Some(name);
                current_value = Some(val);
            }
        }

        // Push final header
        if let (Some(name), Some(val)) = (current_name, current_value) {
            let canon_name = canonicalize_header_name(&name);
            header_map.insert(canon_name.to_lowercase(), val.clone());
            headers.push(SipHeader {
                name: canon_name,
                value: val,
            });
        }

        let body_bytes = body_part.as_bytes().to_vec();

        Some(SipMessage {
            msg_type,
            headers,
            header_map,
            body: body_bytes,
            raw: raw_str.to_string(),
        })
    }

    /// Extract Call-ID header (RFC 3261 header or compact 'i')
    pub fn call_id(&self) -> Option<&str> {
        self.get_header("call-id")
    }

    /// Extract From header (RFC 3261 header or compact 'f')
    pub fn from(&self) -> Option<&str> {
        self.get_header("from")
    }

    /// Extract To header (RFC 3261 header or compact 't')
    pub fn to(&self) -> Option<&str> {
        self.get_header("to")
    }

    /// Extract CSeq header
    pub fn cseq(&self) -> Option<&str> {
        self.get_header("cseq")
    }

    /// Extract User-Agent header
    pub fn user_agent(&self) -> Option<&str> {
        self.get_header("user-agent")
            .or_else(|| self.get_header("server"))
    }

    /// Extract Content-Type header (RFC 3261 header or compact 'c')
    pub fn content_type(&self) -> Option<&str> {
        self.get_header("content-type")
    }

    /// Case-insensitive lookup for a header
    pub fn get_header(&self, name: &str) -> Option<&str> {
        let key = canonicalize_header_name(name).to_lowercase();
        self.header_map.get(&key).map(|s| s.as_str())
    }

    /// Returns a short human-readable summary label (e.g. "INVITE" or "200 OK")
    pub fn summary_label(&self) -> String {
        match &self.msg_type {
            SipType::Request(req) => req.method.as_str().to_string(),
            SipType::Response(resp) => format!("{} {}", resp.status_code, resp.reason),
        }
    }

    /// Returns method name regardless of whether it is a request or extracted from CSeq of a response
    pub fn cseq_method(&self) -> Option<String> {
        match &self.msg_type {
            SipType::Request(req) => Some(req.method.as_str().to_string()),
            SipType::Response(_) => {
                if let Some(cseq) = self.cseq() {
                    let parts: Vec<&str> = cseq.split_whitespace().collect();
                    if parts.len() >= 2 {
                        return Some(parts[1].to_uppercase());
                    }
                }
                None
            }
        }
    }

    /// Extracts clean URI from "Display Name <sip:alice@domain>" or "sip:alice@domain"
    pub fn clean_uri(header_val: &str) -> String {
        if let Some(start) = header_val.find('<') {
            if let Some(end) = header_val.find('>') {
                if start < end {
                    let uri = &header_val[start + 1..end];
                    return uri.split(';').next().unwrap_or(uri).to_string();
                }
            }
        }
        let clean = header_val.split(';').next().unwrap_or(header_val).trim();
        clean.to_string()
    }
}

/// Canonicalize compact SIP headers to standard RFC 3261 names
pub fn canonicalize_header_name(name: &str) -> String {
    match name.to_lowercase().as_str() {
        "i" | "call-id" => "Call-ID".to_string(),
        "f" | "from" => "From".to_string(),
        "t" | "to" => "To".to_string(),
        "v" | "via" => "Via".to_string(),
        "c" | "content-type" => "Content-Type".to_string(),
        "l" | "content-length" => "Content-Length".to_string(),
        "m" | "contact" => "Contact".to_string(),
        "s" | "subject" => "Subject".to_string(),
        "k" | "supported" => "Supported".to_string(),
        "u" | "allow-events" => "Allow-Events".to_string(),
        "o" | "event" => "Event".to_string(),
        "e" | "content-encoding" => "Content-Encoding".to_string(),
        _ => {
            // Capitalize standard Header-Names nicely
            let mut result = String::new();
            let mut capitalize_next = true;
            for ch in name.chars() {
                if ch == '-' {
                    result.push('-');
                    capitalize_next = true;
                } else if capitalize_next {
                    result.extend(ch.to_uppercase());
                    capitalize_next = false;
                } else {
                    result.extend(ch.to_lowercase());
                }
            }
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invite_request() {
        let msg_str = "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.example.com>\r\n\
From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@pc33.atlanta.example.com>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 142\r\n\
\r\n\
v=0\r\no=alice 2890844526 2890844526 IN IP4 pc33.atlanta.example.com\r\ns=\r\nc=IN IP4 pc33.atlanta.example.com\r\nt=0 0\r\nm=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

        let msg = SipMessage::parse_str(msg_str).expect("Should parse SIP INVITE");
        assert_eq!(msg.call_id(), Some("a84b4c76e66710@pc33.atlanta.example.com"));
        assert_eq!(msg.summary_label(), "INVITE");
        assert_eq!(
            SipMessage::clean_uri(msg.from().unwrap()),
            "sip:alice@atlanta.example.com"
        );
        assert_eq!(
            SipMessage::clean_uri(msg.to().unwrap()),
            "sip:bob@biloxi.example.com"
        );
        assert!(!msg.body.is_empty());
    }

    #[test]
    fn test_parse_compact_headers() {
        let msg_str = "SIP/2.0 200 OK\r\n\
v: SIP/2.0/UDP client.domain.com:5060;branch=z9hG4bK-1\r\n\
t: <sip:callee@domain.com>;tag=abc\r\n\
f: <sip:caller@domain.com>;tag=xyz\r\n\
i: test-call-id-9988\r\n\
CSeq: 1 INVITE\r\n\
l: 0\r\n\
\r\n";

        let msg = SipMessage::parse_str(msg_str).expect("Should parse SIP 200 OK");
        assert_eq!(msg.call_id(), Some("test-call-id-9988"));
        assert_eq!(msg.summary_label(), "200 OK");
        assert_eq!(msg.cseq_method().as_deref(), Some("INVITE"));
    }
}
