use std::net::SocketAddr;
use chrono::Local;

// We include the internal modules for unit / integration tests
#[path = "../src/sip/mod.rs"]
mod sip;

use sip::call::{CallEndpoint, CallManager, CallPacket, CallState};
use sip::parser::SipMessage;

fn make_packet(num: usize, src_str: &str, dst_str: &str, raw_sip: &str) -> CallPacket {
    let src: SocketAddr = src_str.parse().unwrap();
    let dst: SocketAddr = dst_str.parse().unwrap();
    let msg = SipMessage::parse_str(raw_sip).expect("Valid SIP message");

    CallPacket {
        packet_num: num,
        timestamp: Local::now(),
        src: CallEndpoint::new(src),
        dst: CallEndpoint::new(dst),
        transport: "UDP".to_string(),
        message: msg,
    }
}

#[test]
fn test_full_invite_call_flow_lifecycle() {
    let mut manager = CallManager::new();

    let client_ep = "192.168.1.100:5060";
    let server_ep = "192.168.1.1:5060";
    let call_id = "test-call-id-12345@192.168.1.100";

    // 1. INVITE
    let invite_sip = format!(
        "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-inv-1\r\n\
From: Alice <sip:alice@biloxi.example.com>;tag=alice-tag\r\n\
To: Bob <sip:bob@biloxi.example.com>\r\n\
Call-ID: {call_id}\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.100:5060>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 20\r\n\
\r\n\
v=0\r\nm=audio 4000 RTP\r\n"
    );
    manager.handle_packet(make_packet(1, client_ep, server_ep, &invite_sip));

    assert_eq!(manager.calls().len(), 1);
    let call = &manager.calls()[0];
    assert_eq!(call.call_id, call_id);
    assert_eq!(call.state, CallState::Setup);
    assert_eq!(call.caller, "sip:alice@biloxi.example.com");
    assert_eq!(call.callee, "sip:bob@biloxi.example.com");

    // 2. 100 Trying
    let trying_sip = format!(
        "SIP/2.0 100 Trying\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-inv-1\r\n\
From: Alice <sip:alice@biloxi.example.com>;tag=alice-tag\r\n\
To: Bob <sip:bob@biloxi.example.com>\r\n\
Call-ID: {call_id}\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    manager.handle_packet(make_packet(2, server_ep, client_ep, &trying_sip));
    assert_eq!(manager.calls()[0].state, CallState::Trying);

    // 3. 180 Ringing
    let ringing_sip = format!(
        "SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-inv-1\r\n\
From: Alice <sip:alice@biloxi.example.com>;tag=alice-tag\r\n\
To: Bob <sip:bob@biloxi.example.com>;tag=bob-tag\r\n\
Call-ID: {call_id}\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    manager.handle_packet(make_packet(3, server_ep, client_ep, &ringing_sip));
    assert_eq!(manager.calls()[0].state, CallState::Ringing);

    // 4. 200 OK
    let ok_sip = format!(
        "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-inv-1\r\n\
From: Alice <sip:alice@biloxi.example.com>;tag=alice-tag\r\n\
To: Bob <sip:bob@biloxi.example.com>;tag=bob-tag\r\n\
Call-ID: {call_id}\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    manager.handle_packet(make_packet(4, server_ep, client_ep, &ok_sip));
    assert_eq!(manager.calls()[0].state, CallState::Established);

    // 5. ACK
    let ack_sip = format!(
        "ACK sip:bob@192.168.1.1:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-ack-1\r\n\
From: Alice <sip:alice@biloxi.example.com>;tag=alice-tag\r\n\
To: Bob <sip:bob@biloxi.example.com>;tag=bob-tag\r\n\
Call-ID: {call_id}\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    manager.handle_packet(make_packet(5, client_ep, server_ep, &ack_sip));
    assert_eq!(manager.calls()[0].state, CallState::Established);

    // 6. BYE
    let bye_sip = format!(
        "BYE sip:alice@192.168.1.100:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-bye-1\r\n\
From: Bob <sip:bob@biloxi.example.com>;tag=bob-tag\r\n\
To: Alice <sip:alice@biloxi.example.com>;tag=alice-tag\r\n\
Call-ID: {call_id}\r\n\
CSeq: 100 BYE\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    manager.handle_packet(make_packet(6, server_ep, client_ep, &bye_sip));
    assert_eq!(manager.calls()[0].state, CallState::Terminated);

    // Ladder verification
    let steps = manager.calls()[0].ladder_steps();
    assert_eq!(steps.len(), 6);
    assert_eq!(steps[0].label, "INVITE");
    assert_eq!(steps[1].label, "100 Trying");
    assert_eq!(steps[2].label, "180 Ringing");
    assert_eq!(steps[3].label, "200 OK");
    assert_eq!(steps[4].label, "ACK");
    assert_eq!(steps[5].label, "BYE");
}

#[test]
fn test_registration_flow() {
    let mut manager = CallManager::new();
    let reg_call_id = "reg-id-9988@domain.com";

    let reg_req = format!(
        "REGISTER sip:registrar.domain.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-reg-1\r\n\
From: <sip:user100@domain.com>;tag=1234\r\n\
To: <sip:user100@domain.com>\r\n\
Call-ID: {reg_call_id}\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:user100@10.0.0.2:5060>\r\n\
Expires: 3600\r\n\
Content-Length: 0\r\n\
\r\n"
    );

    manager.handle_packet(make_packet(1, "10.0.0.2:5060", "10.0.0.1:5060", &reg_req));
    assert_eq!(manager.calls()[0].state, CallState::Register);

    let reg_ok = format!(
        "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-reg-1\r\n\
From: <sip:user100@domain.com>;tag=1234\r\n\
To: <sip:user100@domain.com>;tag=server-tag\r\n\
Call-ID: {reg_call_id}\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:user100@10.0.0.2:5060>;expires=3600\r\n\
Content-Length: 0\r\n\
\r\n"
    );

    manager.handle_packet(make_packet(2, "10.0.0.1:5060", "10.0.0.2:5060", &reg_ok));
    assert_eq!(manager.calls()[0].state, CallState::Registered);
}
