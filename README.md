# sipgrep-rs 🦀

[![Crates.io](https://img.shields.io/crates/v/sipgrep-rs.svg)](https://crates.io/crates/sipgrep-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![RFC 3261](https://img.shields.io/badge/SIP-RFC%203261-orange.svg)](https://datatracker.ietf.org/doc/html/rfc3261)
[![Website](https://img.shields.io/badge/Live-Demo%20%26%20Docs-cyan.svg)](https://mahirgul.github.io/sipgrep-rs/)

A fast, memory-safe, modern terminal-based **SIP (Session Initiation Protocol)** packet sniffer, call flow ladder visualizer, and protocol analyzer written in 100% Rust.

Inspired by the classic `sngrep` tool, `sipgrep-rs` is a **clean-room rewrite** implemented from scratch based solely on the official IETF specifications (**RFC 3261**, RFC 3262, RFC 3265, RFC 3428, and SDP RFC 4566). It contains zero GPL code and is fully licensed under the permissive **MIT License**.

---

## ✨ Features

- **Live Capture & PCAP Replay**: Capture live VoIP traffic on any network interface or analyze recorded `.pcap` / `.pcapng` files.
- **Clean-Room RFC 3261 Parser**: Robust parsing of SIP Requests, Responses, standard headers, and compact headers (`i`, `f`, `t`, `v`, `c`, `l`, `m`).
- **Call Dialog & Flow Tracking**: Automatically correlates packets by `Call-ID` and maintains dialog state machines (INVITE, 100 Trying, 180 Ringing, 200 OK, ACK, BYE, CANCEL, REGISTER, OPTIONS, etc.).
- **Interactive Call Ladder Diagrams**: ASCII/Unicode ladder diagram showing the chronological sequence of message exchanges between endpoints with directional arrows and color coding.
- **Raw SIP Inspector**: Syntax-highlighted view of SIP message headers and SDP body.
- **Interactive Real-Time Search**: Search & filter calls dynamically by Call-ID, IP address, Caller URI, Callee URI, or Method.
- **Headless & Scripting Modes**:
  - `--dump`: Stream captured SIP packets to stdout.
  - `--ladder`: Output ASCII call flow ladders directly to stdout for logs, automated tests, or CI pipelines.

---

## 🚀 Quick Start

### Prerequisites
- Rust 1.80+ (with Cargo)
- `libpcap-dev` on Linux (or WinPcap/Npcap on Windows)

```bash
# Ubuntu / Debian
sudo apt-get install -y libpcap-dev build-essential
```

### Installation & Build

```bash
git clone https://github.com/mahirgul/sipgrep-rs.git
cd sipgrep-rs
cargo build --release
```

The compiled binary will be located at `target/release/sipgrep-rs`.

---

## 📖 Usage

### 1. Live Capture (Default Port 5060)
```bash
sudo ./target/release/sipgrep-rs -i eth0
```

### 2. Capture on Custom Port with BPF Filter
```bash
sudo ./target/release/sipgrep-rs -i any -p 5080 -f "udp port 5080 or tcp port 5080"
```

### 3. Analyze Offline PCAP Capture
```bash
./target/release/sipgrep-rs -r traffic.pcap
```

### 4. CLI Headless Mode (Stream to Terminal)
```bash
sudo ./target/release/sipgrep-rs -i eth0 --dump
```

### 5. CLI Call Ladder Summary
```bash
./target/release/sipgrep-rs -r call.pcap --ladder
```

---

## ⌨️ TUI Keyboard Controls

| Key | Description |
|---|---|
| `Enter` | Open Call Flow ladder diagram for selected call / View full message |
| `Esc` / `b` | Back to previous view / Clear active search filter |
| `Up` / `k` | Move cursor up in call list or ladder steps |
| `Down` / `j` | Move cursor down in call list or ladder steps |
| `/` | Open interactive real-time filter input |
| `Space` | Pause / Resume live packet capture |
| `c` | Clear current call history |
| `d` | Inspect raw SIP headers and SDP payload |
| `h` / `?` | Toggle Help modal |
| `q` | Quit application |

---

## 🏗️ Architecture

```
sipgrep-rs
├── src/
│   ├── main.rs         # CLI argument parsing, terminal lifecycle & event loop
│   ├── capture/
│   │   └── mod.rs      # libpcap sniffer, etherparse packet decoder & dispatch
│   ├── sip/
│   │   ├── mod.rs      # SIP protocol module exports
│   │   ├── parser.rs   # Clean-room RFC 3261 parser (requests, responses, headers)
│   │   └── call.rs     # Dialog tracking, state machine & ladder step generator
│   └── ui/
│       ├── mod.rs      # TUI module
│       ├── app.rs      # State management, view router & key event handling
│       └── render.rs   # Ratatui widgets (Call Table, Ladder Diagram, Raw Inspector)
└── tests/
    └── integration_tests.rs # Full RFC 3261 call flow & dialog tests
```

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
