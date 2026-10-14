//! Application state and input management for the sipgrep-rs TUI.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crossbeam_channel::Receiver;
use crossterm::event::{KeyCode, KeyEvent};

use crate::sip::{Call, CallManager, CallPacket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    CallList,
    FlowLadder,
    MessageDetail,
    Help,
}

pub struct App {
    pub call_manager: CallManager,
    pub view_mode: ViewMode,
    pub selected_call_idx: usize,
    pub selected_packet_idx: usize,
    pub filter_text: String,
    pub filter_mode: bool,
    pub paused: bool,
    pub should_quit: bool,
    pub status_message: Option<String>,
    pub source_info: String,
    pub receiver: Receiver<CallPacket>,
    pub running: Arc<AtomicBool>,
}

impl App {
    pub fn new(
        receiver: Receiver<CallPacket>,
        running: Arc<AtomicBool>,
        source_info: String,
    ) -> Self {
        Self {
            call_manager: CallManager::new(),
            view_mode: ViewMode::CallList,
            selected_call_idx: 0,
            selected_packet_idx: 0,
            filter_text: String::new(),
            filter_mode: false,
            paused: false,
            should_quit: false,
            status_message: None,
            source_info,
            receiver,
            running,
        }
    }

    /// Process incoming packets from background capture thread
    pub fn update(&mut self) {
        while let Ok(packet) = self.receiver.try_recv() {
            if !self.paused {
                self.call_manager.handle_packet(packet);
            }
        }
    }

    /// Selected call reference
    pub fn current_call(&self) -> Option<&Call> {
        let filtered = self.call_manager.filter_calls(&self.filter_text);
        filtered.get(self.selected_call_idx).map(|(_, c)| *c)
    }

    /// Selected packet reference in FlowLadder view
    pub fn current_ladder_packet(&self) -> Option<&CallPacket> {
        let call = self.current_call()?;
        call.packets.get(self.selected_packet_idx)
    }

    /// Handle key input events
    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.filter_mode {
            self.handle_filter_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.should_quit = true;
                self.running.store(false, Ordering::Relaxed);
            }
            KeyCode::Char('h') | KeyCode::Char('?') => {
                self.view_mode = if self.view_mode == ViewMode::Help {
                    ViewMode::CallList
                } else {
                    ViewMode::Help
                };
            }
            KeyCode::Char('/') => {
                self.filter_mode = true;
            }
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                self.status_message = Some(if self.paused {
                    "Capture Paused".to_string()
                } else {
                    "Capture Resumed".to_string()
                });
            }
            KeyCode::Char('c') => {
                self.call_manager.clear();
                self.selected_call_idx = 0;
                self.selected_packet_idx = 0;
                self.status_message = Some("Cleared all calls".to_string());
            }
            KeyCode::Esc | KeyCode::Char('b') => {
                match self.view_mode {
                    ViewMode::CallList => {
                        if !self.filter_text.is_empty() {
                            self.filter_text.clear();
                            self.selected_call_idx = 0;
                        }
                    }
                    ViewMode::FlowLadder => {
                        self.view_mode = ViewMode::CallList;
                    }
                    ViewMode::MessageDetail => {
                        self.view_mode = ViewMode::FlowLadder;
                    }
                    ViewMode::Help => {
                        self.view_mode = ViewMode::CallList;
                    }
                }
            }
            KeyCode::Enter => match self.view_mode {
                ViewMode::CallList => {
                    if self.current_call().is_some() {
                        self.selected_packet_idx = 0;
                        self.view_mode = ViewMode::FlowLadder;
                    }
                }
                ViewMode::FlowLadder => {
                    if self.current_ladder_packet().is_some() {
                        self.view_mode = ViewMode::MessageDetail;
                    }
                }
                _ => {}
            },
            KeyCode::Char('d') => {
                if self.view_mode == ViewMode::FlowLadder && self.current_ladder_packet().is_some()
                {
                    self.view_mode = ViewMode::MessageDetail;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_up();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_down();
            }
            KeyCode::Home => {
                if self.view_mode == ViewMode::CallList {
                    self.selected_call_idx = 0;
                } else if self.view_mode == ViewMode::FlowLadder {
                    self.selected_packet_idx = 0;
                }
            }
            KeyCode::End => {
                if self.view_mode == ViewMode::CallList {
                    let total = self.call_manager.filter_calls(&self.filter_text).len();
                    if total > 0 {
                        self.selected_call_idx = total - 1;
                    }
                } else if self.view_mode == ViewMode::FlowLadder {
                    if let Some(call) = self.current_call() {
                        if !call.packets.is_empty() {
                            self.selected_packet_idx = call.packets.len() - 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.filter_mode = false;
            }
            KeyCode::Backspace => {
                self.filter_text.pop();
                self.selected_call_idx = 0;
            }
            KeyCode::Char(c) => {
                self.filter_text.push(c);
                self.selected_call_idx = 0;
            }
            _ => {}
        }
    }

    fn move_up(&mut self) {
        match self.view_mode {
            ViewMode::CallList => {
                if self.selected_call_idx > 0 {
                    self.selected_call_idx -= 1;
                }
            }
            ViewMode::FlowLadder => {
                if self.selected_packet_idx > 0 {
                    self.selected_packet_idx -= 1;
                }
            }
            _ => {}
        }
    }

    fn move_down(&mut self) {
        match self.view_mode {
            ViewMode::CallList => {
                let count = self.call_manager.filter_calls(&self.filter_text).len();
                if count > 0 && self.selected_call_idx + 1 < count {
                    self.selected_call_idx += 1;
                }
            }
            ViewMode::FlowLadder => {
                if let Some(call) = self.current_call() {
                    if self.selected_packet_idx + 1 < call.packets.len() {
                        self.selected_packet_idx += 1;
                    }
                }
            }
            _ => {}
        }
    }
}
