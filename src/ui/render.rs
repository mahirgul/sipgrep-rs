//! Ratatui UI rendering components for sipgrep-rs.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};

use crate::sip::CallState;
use crate::ui::app::{App, ViewMode};

pub fn draw(frame: &mut Frame, app: &mut App) {
    let size = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(5),    // Main content
            Constraint::Length(2), // Footer / shortcut bar
        ])
        .split(size);

    draw_header(frame, app, chunks[0]);

    match app.view_mode {
        ViewMode::CallList => draw_call_list(frame, app, chunks[1]),
        ViewMode::FlowLadder => draw_flow_ladder(frame, app, chunks[1]),
        ViewMode::MessageDetail => draw_message_detail(frame, app, chunks[1]),
        ViewMode::Help => {
            draw_call_list(frame, app, chunks[1]);
            draw_help_modal(frame);
        }
    }

    draw_footer(frame, app, chunks[2]);
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let total_calls = app.call_manager.calls().len();
    let total_msgs = app.call_manager.total_messages();

    let status_str = if app.paused {
        Span::styled(" [PAUSED] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" [LIVE] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    };

    let title = Line::from(vec![
        Span::styled(" sipgrep-rs ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("| Source: "),
        Span::styled(&app.source_info, Style::default().fg(Color::White)),
        Span::raw(" | Calls: "),
        Span::styled(total_calls.to_string(), Style::default().fg(Color::Yellow)),
        Span::raw(" | Msgs: "),
        Span::styled(total_msgs.to_string(), Style::default().fg(Color::Yellow)),
        status_str,
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Cyan));

    let filter_display = if app.filter_mode {
        Line::from(vec![
            Span::styled("FILTER (typing): ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(&app.filter_text),
            Span::styled(" █", Style::default().fg(Color::Yellow)),
        ])
    } else if !app.filter_text.is_empty() {
        Line::from(vec![
            Span::styled("FILTER: ", Style::default().fg(Color::Yellow)),
            Span::raw(&app.filter_text),
            Span::styled("  (Press '/' to edit, 'Esc' to clear)", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::raw("RFC 3261 Terminal SIP Protocol & Call Flow Analyzer | Press 'h' for help"),
        ])
    };

    let p = Paragraph::new(filter_display).block(block);
    frame.render_widget(p, area);
}

fn draw_call_list(frame: &mut Frame, app: &App, area: Rect) {
    let filtered_calls = app.call_manager.filter_calls(&app.filter_text);

    let header_cells = [
        "#", "Time", "Method", "State", "Caller (From)", "Callee (To)", "Msgs", "Duration", "Call-ID",
    ]
    .iter()
    .map(|h| Span::styled(*h, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(0);

    let rows: Vec<Row> = filtered_calls
        .iter()
        .enumerate()
        .map(|(disp_idx, (_, call))| {
            let is_selected = disp_idx == app.selected_call_idx;

            let (state_color, state_str) = match &call.state {
                CallState::Established | CallState::Registered => (Color::Green, call.state.label()),
                CallState::Ringing | CallState::Trying => (Color::Yellow, call.state.label()),
                CallState::Rejected => (Color::Red, call.state.label()),
                CallState::Cancelled | CallState::Terminated => (Color::DarkGray, call.state.label()),
                _ => (Color::Cyan, call.state.label()),
            };

            let row_style = if is_selected {
                Style::default().bg(Color::Rgb(30, 60, 90)).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let cells = vec![
                Span::raw(format!("{:>3}", disp_idx + 1)),
                Span::raw(call.start_time.format("%H:%M:%S").to_string()),
                Span::styled(&call.initial_method, Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
                Span::styled(state_str, Style::default().fg(state_color)),
                Span::raw(&call.caller),
                Span::raw(&call.callee),
                Span::raw(format!("{:>3}", call.packets.len())),
                Span::raw(call.duration_str()),
                Span::styled(&call.call_id, Style::default().fg(Color::Gray)),
            ];

            Row::new(cells).style(row_style).height(1)
        })
        .collect();

    let widths = [
        Constraint::Length(5),   // #
        Constraint::Length(10),  // Time
        Constraint::Length(10),  // Method
        Constraint::Length(15),  // State
        Constraint::Percentage(20), // From
        Constraint::Percentage(20), // To
        Constraint::Length(6),   // Msgs
        Constraint::Length(10),  // Duration
        Constraint::Min(20),     // Call-ID
    ];

    let title = format!(" Captured Calls ({}) ", filtered_calls.len());
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .column_spacing(1);

    frame.render_widget(table, area);
}

fn draw_flow_ladder(frame: &mut Frame, app: &App, area: Rect) {
    let call = match app.current_call() {
        Some(c) => c,
        None => {
            let p = Paragraph::new("No call selected")
                .block(Block::default().borders(Borders::ALL).title(" Call Flow "));
            frame.render_widget(p, area);
            return;
        }
    };

    // Split into Ladder Diagram (top 60%) and Message Preview (bottom 40%)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    // Render Ladder
    draw_ladder_diagram(frame, app, call, chunks[0]);

    // Render Message Preview
    draw_packet_preview(frame, app, call, chunks[1]);
}

fn draw_ladder_diagram(frame: &mut Frame, app: &App, call: &crate::sip::Call, area: Rect) {
    let endpoints = &call.endpoints;
    let steps = call.ladder_steps();

    let mut lines = Vec::new();

    // Top Header: Endpoints columns
    let mut ep_line = String::from("  Time       ");
    for (i, ep) in endpoints.iter().enumerate() {
        let ep_str = format!("[EP{i}: {}]", ep.addr);
        ep_line.push_str(&format!("{:<28}", ep_str));
    }
    lines.push(Line::from(Span::styled(ep_line, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));

    // Separator
    let sep = "─".repeat(area.width.saturating_sub(4) as usize);
    lines.push(Line::from(Span::styled(sep, Style::default().fg(Color::DarkGray))));

    // Message arrows
    for (idx, step) in steps.iter().enumerate() {
        let is_selected = idx == app.selected_packet_idx;
        let time_str = step.timestamp.format("%H:%M:%S%.3f").to_string();

        let prefix = if is_selected { "► " } else { "  " };

        let arrow_color = if let Some(code) = step.status_code {
            match code {
                100..=199 => Color::Yellow,
                200..=299 => Color::Green,
                300..=399 => Color::Blue,
                _ => Color::Red,
            }
        } else {
            Color::Cyan
        };

        // Build ASCII ladder arrow between endpoints
        let arrow = if step.src_idx <= step.dst_idx {
            // Left to Right: |────── INVITE ──────>|
            format!("|{:=^26}>|", format!(" {} ", step.label))
        } else {
            // Right to Left: |<───── 200 OK ──────|
            format!("|<{:=^26}|", format!(" {} ", step.label))
        };

        let style = if is_selected {
            Style::default().bg(Color::Rgb(30, 60, 90)).fg(Color::White).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(arrow_color)
        };

        let line_content = format!("{prefix}{time_str}   {arrow}");
        lines.push(Line::from(Span::styled(line_content, style)));
    }

    let title = format!(" Call Flow: {} ({} messages) ", call.call_id, steps.len());
    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false });

    frame.render_widget(p, area);
}

fn draw_packet_preview(frame: &mut Frame, app: &App, call: &crate::sip::Call, area: Rect) {
    let packet = match call.packets.get(app.selected_packet_idx) {
        Some(p) => p,
        None => {
            let p = Paragraph::new("No packet selected")
                .block(Block::default().borders(Borders::ALL).title(" Message Preview "));
            frame.render_widget(p, area);
            return;
        }
    };

    let title = format!(
        " Message Preview (Msg #{} - {} -> {}) [Press 'Enter' or 'd' for Full View] ",
        packet.packet_num, packet.src.addr, packet.dst.addr
    );

    let mut lines = Vec::new();
    for (i, line_str) in packet.message.raw.lines().enumerate() {
        if i == 0 {
            lines.push(Line::from(Span::styled(
                line_str,
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
        } else if line_str.is_empty() {
            lines.push(Line::from(Span::styled("--- Message Body ---", Style::default().fg(Color::DarkGray))));
        } else if let Some(colon) = line_str.find(':') {
            let header_name = &line_str[..colon];
            let header_val = &line_str[colon..];
            lines.push(Line::from(vec![
                Span::styled(header_name, Style::default().fg(Color::Cyan)),
                Span::raw(header_val),
            ]));
        } else {
            lines.push(Line::from(Span::raw(line_str)));
        }
    }

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false });

    frame.render_widget(p, area);
}

fn draw_message_detail(frame: &mut Frame, app: &App, area: Rect) {
    let call = match app.current_call() {
        Some(c) => c,
        None => return,
    };

    let packet = match call.packets.get(app.selected_packet_idx) {
        Some(p) => p,
        None => return,
    };

    let title = format!(
        " Raw SIP Inspector: Msg #{} ({} -> {}) [Esc: Return to Flow] ",
        packet.packet_num, packet.src.addr, packet.dst.addr
    );

    let mut lines = Vec::new();
    for (i, line_str) in packet.message.raw.lines().enumerate() {
        let line_num = format!("{:>3} │ ", i + 1);
        if i == 0 {
            lines.push(Line::from(vec![
                Span::styled(line_num, Style::default().fg(Color::DarkGray)),
                Span::styled(line_str, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]));
        } else if line_str.is_empty() {
            lines.push(Line::from(vec![
                Span::styled(line_num, Style::default().fg(Color::DarkGray)),
                Span::styled("─────── SDP / Payload ───────", Style::default().fg(Color::Magenta)),
            ]));
        } else if let Some(colon) = line_str.find(':') {
            let header_name = &line_str[..colon];
            let header_val = &line_str[colon..];
            lines.push(Line::from(vec![
                Span::styled(line_num, Style::default().fg(Color::DarkGray)),
                Span::styled(header_name, Style::default().fg(Color::Cyan)),
                Span::raw(header_val),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled(line_num, Style::default().fg(Color::DarkGray)),
                Span::raw(line_str),
            ]));
        }
    }

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false });

    frame.render_widget(p, area);
}

fn draw_help_modal(frame: &mut Frame) {
    let area = centered_rect(65, 60, frame.area());
    frame.render_widget(Clear, area);

    let help_text = vec![
        Line::from(Span::styled("sipgrep-rs Navigation & Hotkeys", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![Span::styled("  Enter    ", Style::default().fg(Color::Yellow)), Span::raw("Open Call Flow ladder diagram / View Raw Details")]),
        Line::from(vec![Span::styled("  Esc / b  ", Style::default().fg(Color::Yellow)), Span::raw("Back to previous view / Clear active filter")]),
        Line::from(vec![Span::styled("  Up / k   ", Style::default().fg(Color::Yellow)), Span::raw("Navigate up in call list / flow steps")]),
        Line::from(vec![Span::styled("  Down / j ", Style::default().fg(Color::Yellow)), Span::raw("Navigate down in call list / flow steps")]),
        Line::from(vec![Span::styled("  /        ", Style::default().fg(Color::Yellow)), Span::raw("Interactive search / filter by Call-ID, IP, Method, URI")]),
        Line::from(vec![Span::styled("  Space    ", Style::default().fg(Color::Yellow)), Span::raw("Pause / Resume live packet capture")]),
        Line::from(vec![Span::styled("  c        ", Style::default().fg(Color::Yellow)), Span::raw("Clear call history")]),
        Line::from(vec![Span::styled("  d        ", Style::default().fg(Color::Yellow)), Span::raw("Inspect full raw SIP headers & SDP body")]),
        Line::from(vec![Span::styled("  h / ?    ", Style::default().fg(Color::Yellow)), Span::raw("Toggle this help popup")]),
        Line::from(vec![Span::styled("  q        ", Style::default().fg(Color::Yellow)), Span::raw("Quit sipgrep-rs")]),
        Line::from(""),
        Line::from(Span::styled("Press 'Esc' or 'h' to close help", Style::default().fg(Color::DarkGray))),
    ];

    let p = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title(" Keyboard Shortcuts "))
        .alignment(Alignment::Left);

    frame.render_widget(p, area);
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let shortcuts = match app.view_mode {
        ViewMode::CallList => " [Enter] Flow Ladder  [/] Filter  [Space] Pause  [c] Clear  [h] Help  [q] Quit ",
        ViewMode::FlowLadder => " [Enter/d] Inspect Msg  [Esc/b] Call List  [Up/Down] Steps  [Space] Pause  [q] Quit ",
        ViewMode::MessageDetail => " [Esc/b] Back to Flow  [Up/Down] Scroll  [q] Quit ",
        ViewMode::Help => " [Esc/h] Close Help  [q] Quit ",
    };

    let p = Paragraph::new(shortcuts)
        .style(Style::default().bg(Color::Rgb(20, 20, 20)).fg(Color::Cyan))
        .alignment(Alignment::Center);

    frame.render_widget(p, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
