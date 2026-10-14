use std::io::{self, stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel::unbounded;
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

mod capture;
mod sip;
mod ui;

use capture::{start_capture, CaptureConfig};
use sip::{CallManager, CallPacket};
use ui::{App, draw};

/// sipgrep-rs: Modern terminal SIP packet sniffer & call flow ladder analyzer
#[derive(Parser, Debug)]
#[command(author, version, about = "Clean-room RFC 3261 SIP Packet Sniffer & Call Flow Visualizer in Rust", long_about = None)]
pub struct CliArgs {
    /// Network interface to capture from (e.g., eth0, any, lo)
    #[arg(short = 'i', long = "interface")]
    pub interface: Option<String>,

    /// Read packets from offline PCAP capture file
    #[arg(short = 'r', long = "input")]
    pub pcap_file: Option<String>,

    /// SIP UDP/TCP Port to capture (default: 5060)
    #[arg(short = 'p', long = "port", default_value_t = 5060)]
    pub port: u16,

    /// Custom BPF filter (e.g. "port 5060 or port 5061")
    #[arg(short = 'f', long = "filter")]
    pub bpf_filter: Option<String>,

    /// Print captured SIP packets to stdout without launching TUI
    #[arg(long = "dump")]
    pub dump: bool,

    /// Output ASCII call ladder flow directly to stdout
    #[arg(long = "ladder")]
    pub ladder: bool,
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    // Setup Ctrl+C handler
    ctrlc::set_handler(move || {
        r_clone.store(false, Ordering::Relaxed);
    }).expect("Error setting Ctrl-C handler");

    let source_info = if let Some(ref file) = args.pcap_file {
        format!("PCAP: {file}")
    } else if let Some(ref iface) = args.interface {
        format!("Interface: {iface} (port {})", args.port)
    } else {
        format!("Default IF (port {})", args.port)
    };

    let config = CaptureConfig {
        interface: args.interface,
        pcap_file: args.pcap_file,
        bpf_filter: args.bpf_filter,
        port: args.port,
        buffer_size: 4 * 1024 * 1024,
        promisc: true,
    };

    let (tx, rx) = unbounded::<CallPacket>();

    // Start background capture thread
    let _capture_handle = start_capture(config, tx, Arc::clone(&running))?;

    // Non-interactive dump mode
    if args.dump || args.ladder {
        run_cli_dump(rx, running, args.ladder)?;
        return Ok(());
    }

    // Interactive TUI Mode
    run_tui(rx, running, source_info)?;

    Ok(())
}

fn run_cli_dump(
    receiver: crossbeam_channel::Receiver<CallPacket>,
    running: Arc<AtomicBool>,
    ladder_mode: bool,
) -> Result<()> {
    println!("sipgrep-rs: Running in CLI dump mode. Press Ctrl+C to stop.");
    let mut manager = CallManager::new();

    while running.load(Ordering::Relaxed) {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(pkt) => {
                if ladder_mode {
                    println!(
                        "[{}] {:>21} -> {:<21} | {}",
                        pkt.timestamp.format("%H:%M:%S%.3f"),
                        pkt.src.addr,
                        pkt.dst.addr,
                        pkt.message.summary_label()
                    );
                    manager.handle_packet(pkt);
                } else {
                    println!(
                        "[{}] #{} {} -> {} ({}): {}",
                        pkt.timestamp.format("%H:%M:%S%.3f"),
                        pkt.packet_num,
                        pkt.src.addr,
                        pkt.dst.addr,
                        pkt.transport,
                        pkt.message.summary_label()
                    );
                    if let Some(call_id) = pkt.message.call_id() {
                        println!("   Call-ID: {call_id}");
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    if ladder_mode {
        println!("\n=== Final Call Summary ===");
        for (i, call) in manager.calls().iter().enumerate() {
            println!(
                "Call #{}: [{}] {} -> {} ({} messages, duration: {}) Call-ID: {}",
                i + 1,
                call.state.label(),
                call.caller,
                call.callee,
                call.packets.len(),
                call.duration_str(),
                call.call_id
            );
        }
    }

    Ok(())
}

fn run_tui(
    receiver: crossbeam_channel::Receiver<CallPacket>,
    running: Arc<AtomicBool>,
    source_info: String,
) -> Result<()> {
    // Terminal setup
    enable_raw_mode().context("Failed to enable raw mode")?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen).context("Failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Failed to initialize terminal")?;

    // Setup custom panic hook so terminal is restored on any panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));

    let mut app = App::new(receiver, Arc::clone(&running), source_info);

    while running.load(Ordering::Relaxed) && !app.should_quit {
        app.update();

        terminal.draw(|f| draw(f, &mut app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
