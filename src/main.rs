//! ============================================================================
//! sysng - Zero-Bloat System Monitor (GNU/KISS Architecture)
//! Designed for high flexibility, fault tolerance, and cross-platform portability.
//! ============================================================================
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table, Cell},
    Terminal,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io,
    process::Command,
    time::{Duration, Instant},
};
use sysinfo::{Networks, Pid, System};

const SIGNAL_LIST: &[(&str, i32)] = &[
    ("SIGTERM (15 - Graceful termination)", 15),
    ("SIGKILL (9  - Force kill)", 9),
    ("SIGINT  (2  - Interrupt / Ctrl+C)", 2),
    ("SIGHUP  (1  - Hangup / Reload config)", 1),
    ("SIGSTOP (19 - Pause / Stop process)", 19),
    ("SIGCONT (18 - Resume process)", 18),
];

#[allow(dead_code)]
struct FlatRow {
    pid: Pid,
    started: String,
    pid_str: String,
    mem_str: String,
    elapsed: String,
    ni: String,
    cpu_str: String,
    pgrp: String,
    tt: String,
    ruser: String,
    euser: String,
    fuser: String,
    display_command: String,
    cpu_val: f32,
    mem_val: u64,
    depth: usize,
    has_children: bool,
}

struct MetricHistory {
    cpu_history: VecDeque<f32>,
    mem_history: VecDeque<f32>,
    swap_history: VecDeque<f32>,
    #[allow(dead_code)]
    net_rx_history: HashMap<String, VecDeque<u64>>,
    #[allow(dead_code)]
    net_tx_history: HashMap<String, VecDeque<u64>>,
}

struct ApplicationState {
    system_data: System,
    network_data: Networks,
    active_view: Option<usize>,
    search_query: String,
    is_searching: bool,
    backspace_pressed_when_empty: bool,
    is_kill_prompt: bool,
    kill_option_index: usize,
    should_quit: bool,
    quit_confirmation: bool,
    table_scroll_offset: usize,
    selected_row_index: usize,
    is_flat_tree: bool,
    collapsed_pids: HashSet<Pid>,
    show_usb_devices: bool,
    graph_tab_index: usize,
    last_update: Instant,
    last_graph_update: Instant,
    flat_rows_cache: Vec<FlatRow>,
    history: MetricHistory,
    popup_notification: Option<(String, Instant)>,
}

fn initialize_application_state() -> ApplicationState {
    let mut system_instance = System::new_all();
    system_instance.refresh_all();
    let networks_instance = Networks::new_with_refreshed_list();

    ApplicationState {
        system_data: system_instance,
        network_data: networks_instance,
        active_view: None,
        search_query: String::new(),
        is_searching: false,
        backspace_pressed_when_empty: false,
        is_kill_prompt: false,
        kill_option_index: 0,
        should_quit: false,
        quit_confirmation: false,
        table_scroll_offset: 0,
        selected_row_index: 0,
        is_flat_tree: false,
        collapsed_pids: HashSet::new(),
        show_usb_devices: false,
        graph_tab_index: 0,
        last_update: Instant::now(),
        last_graph_update: Instant::now(),
        flat_rows_cache: Vec::new(),
        history: MetricHistory {
            cpu_history: VecDeque::with_capacity(60),
            mem_history: VecDeque::with_capacity(60),
            swap_history: VecDeque::with_capacity(60),
            net_rx_history: HashMap::new(),
            net_tx_history: HashMap::new(),
        },
        popup_notification: None,
    }
}

fn update_process_cache(state: &mut ApplicationState) {
    let mut parent_map: HashMap<Option<Pid>, Vec<(Pid, String, f32, u64, String)>> = HashMap::new();

    for (pid, process) in state.system_data.processes() {
        let name = process.name().to_string_lossy().to_string();
        if name.is_empty()
            || name.starts_with("kworker")
            || name.starts_with("kthreadd")
            || name.starts_with("ksoftirqd")
            || name.starts_with("rcu_")
            || name.starts_with("migration/")
            || name.starts_with("cpuhp/")
        {
            continue;
        }

        let parent_pid = process.parent();
        let cpu = process.cpu_usage();
        let memory = process.memory();
        let user = process.user_id()
            .map(|u| u.to_string())
            .unwrap_or_else(|| "user".to_string());

        parent_map
            .entry(parent_pid)
            .or_default()
            .push((*pid, name, cpu, memory, user));
    }

    let mut flat_out = Vec::new();
    let query_lower = state.search_query.to_lowercase();

    if state.is_searching && !state.search_query.is_empty() {
        for (_, list) in &parent_map {
            for (pid, name, cpu, memory, user) in list {
                let pid_str = pid.to_string();
                let name_lower = name.to_lowercase();

                if name_lower.contains(&query_lower) || pid_str.contains(&query_lower) {
                    let mem_mb = *memory as f64 / 1024.0 / 1024.0;
                    flat_out.push(FlatRow {
                        pid: *pid,
                        started: "00:00".to_string(),
                        pid_str,
                        mem_str: format!("{:.1}MB", mem_mb),
                        elapsed: "00:00".to_string(),
                        ni: "0".to_string(),
                        cpu_str: format!("{:.1}%", cpu),
                        pgrp: "0".to_string(),
                        tt: "-".to_string(),
                        ruser: user.clone(),
                        euser: user.clone(),
                        fuser: "-".to_string(),
                        display_command: format!("- {}", name),
                        cpu_val: *cpu,
                        mem_val: *memory,
                        depth: 0,
                        has_children: false,
                    });
                }
            }
        }
        flat_out.sort_by(|a, b| b.cpu_val.partial_cmp(&a.cpu_val).unwrap_or(std::cmp::Ordering::Equal));
    } else {
        fn build_nodes(
            parent: Option<Pid>,
            depth: usize,
            map: &HashMap<Option<Pid>, Vec<(Pid, String, f32, u64, String)>>,
            out: &mut Vec<FlatRow>,
            collapsed: &HashSet<Pid>,
        ) {
            if let Some(children) = map.get(&parent) {
                for (pid, name, cpu, memory, user) in children {
                    let has_children = map.get(&Some(*pid)).map_or(false, |c| !c.is_empty());
                    let is_collapsed = collapsed.contains(pid);

                    let mut s = String::new();
                    for _ in 0..depth {
                        s.push_str("  ");
                    }
                    if depth > 0 {
                        s.push_str("└─ ");
                    }

                    let indicator = if has_children {
                        if is_collapsed { "[+] " } else { "[-] " }
                    } else {
                        " *  "
                    };

                    let display_command = format!("{}{}{}", s, indicator, name);
                    let mem_mb = *memory as f64 / 1024.0 / 1024.0;

                    out.push(FlatRow {
                        pid: *pid,
                        started: "00:00".to_string(),
                        pid_str: pid.to_string(),
                        mem_str: format!("{:.1}MB", mem_mb),
                        elapsed: "00:00".to_string(),
                        ni: "0".to_string(),
                        cpu_str: format!("{:.1}%", cpu),
                        pgrp: "0".to_string(),
                        tt: "-".to_string(),
                        ruser: user.clone(),
                        euser: user.clone(),
                        fuser: "-".to_string(),
                        display_command,
                        cpu_val: *cpu,
                        mem_val: *memory,
                        depth,
                        has_children,
                    });

                    if has_children && !is_collapsed {
                        build_nodes(Some(*pid), depth + 1, map, out, collapsed);
                    }
                }
            }
        }

        if state.is_flat_tree {
            let mut all_procs = vec![];
            for (_, list) in &parent_map {
                for item in list {
                    all_procs.push(item.clone());
                }
            }
            all_procs.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
            for (pid, name, cpu, memory, user) in all_procs {
                let mem_mb = memory as f64 / 1024.0 / 1024.0;
                flat_out.push(FlatRow {
                    pid,
                    started: "00:00".to_string(),
                    pid_str: pid.to_string(),
                    mem_str: format!("{:.1}MB", mem_mb),
                    elapsed: "00:00".to_string(),
                    ni: "0".to_string(),
                    cpu_str: format!("{:.1}%", cpu),
                    pgrp: "0".to_string(),
                    tt: "-".to_string(),
                    ruser: user.clone(),
                    euser: user.clone(),
                    fuser: "-".to_string(),
                    display_command: format!("- {}", name),
                    cpu_val: cpu,
                    mem_val: memory,
                    depth: 0,
                    has_children: false,
                });
            }
        } else {
            build_nodes(None, 0, &parent_map, &mut flat_out, &state.collapsed_pids);
        }
    }

    state.flat_rows_cache = flat_out;
    if state.selected_row_index >= state.flat_rows_cache.len() && !state.flat_rows_cache.is_empty() {
        state.selected_row_index = state.flat_rows_cache.len() - 1;
    }
}

fn refresh_system_metrics(state: &mut ApplicationState) {
    if state.last_update.elapsed() >= Duration::from_secs(3) {
        state.system_data.refresh_all();
        state.network_data.refresh(true);
        update_process_cache(state);
        state.last_update = Instant::now();
    }

    if state.last_graph_update.elapsed() >= Duration::from_millis(750) {
        let global_cpu = state.system_data.global_cpu_usage();
        let total_mem = state.system_data.total_memory() as f32;
        let used_mem = state.system_data.used_memory() as f32;
        let mem_pct = if total_mem > 0.0 { (used_mem / total_mem) * 100.0 } else { 0.0 };

        let total_swap = state.system_data.total_swap() as f32;
        let used_swap = state.system_data.used_swap() as f32;
        let swap_pct = if total_swap > 0.0 { (used_swap / total_swap) * 100.0 } else { 0.0 };

        if state.history.cpu_history.len() >= 45 {
            state.history.cpu_history.pop_front();
        }
        state.history.cpu_history.push_back(global_cpu);

        if state.history.mem_history.len() >= 45 {
            state.history.mem_history.pop_front();
        }
        state.history.mem_history.push_back(mem_pct);

        if state.history.swap_history.len() >= 45 {
            state.history.swap_history.pop_front();
        }
        state.history.swap_history.push_back(swap_pct);

        state.last_graph_update = Instant::now();
    }
}

fn process_events(state: &mut ApplicationState) -> Result<(), io::Error> {
    while event::poll(Duration::from_millis(10))? {
        match event::read()? {
            Event::Key(key_event) => {
                if state.quit_confirmation {
                    match key_event.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => state.should_quit = true,
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            state.quit_confirmation = false;
                        }
                        _ => {}
                    }
                } else if state.is_kill_prompt {
                    match key_event.code {
                        KeyCode::Esc => {
                            state.is_kill_prompt = false;
                        }
                        KeyCode::Up => {
                            if state.kill_option_index > 0 {
                                state.kill_option_index -= 1;
                            } else {
                                state.kill_option_index = SIGNAL_LIST.len() - 1;
                            }
                        }
                        KeyCode::Down => {
                            state.kill_option_index = (state.kill_option_index + 1) % SIGNAL_LIST.len();
                        }
                        KeyCode::Enter => {
                            if !state.flat_rows_cache.is_empty() {
                                let selected_row = &state.flat_rows_cache[state.selected_row_index];
                                let pid_to_kill = selected_row.pid;
                                let proc_name = selected_row.display_command.trim().to_string();
                                let proc_user = selected_row.ruser.clone();
                                let pid_str = selected_row.pid_str.clone();
                                let sig_name = SIGNAL_LIST[state.kill_option_index].0;
                                let sig_num = SIGNAL_LIST[state.kill_option_index].1;
                                
                                #[cfg(unix)]
                                {
                                    use nix::sys::signal::{kill, Signal};
                                    if let Ok(signal) = Signal::try_from(sig_num) {
                                        let _ = kill(nix::unistd::Pid::from_raw(pid_to_kill.as_u32() as i32), signal);
                                    }
                                }
                                #[cfg(not(unix))]
                                {
                                    if let Some(process) = state.system_data.process(pid_to_kill) {
                                        process.kill();
                                    }
                                }

                                state.system_data.refresh_all();
                                update_process_cache(state);

                                let notification_msg = format!(
                                    "Successfully sent {}\nto PID: {}\nName: {}\nUser: {}",
                                    sig_name, pid_str, proc_name, proc_user
                                );
                                state.popup_notification = Some((notification_msg, Instant::now()));
                            }
                            state.is_kill_prompt = false;
                        }
                        _ => {}
                    }
                } else {
                    match key_event.code {
                        KeyCode::Char('q') | KeyCode::Char('c')
                            if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                            if state.quit_confirmation {
                                state.should_quit = true;
                            } else {
                                state.quit_confirmation = true;
                            }
                        }
                        KeyCode::Char('h') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                            state.active_view = if state.active_view == Some(1) { None } else { Some(1) };
                            state.is_searching = false;
                        }
                        KeyCode::Char('k') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                            if state.active_view.is_none() && !state.flat_rows_cache.is_empty() {
                                state.is_kill_prompt = true;
                                state.kill_option_index = 0;
                            }
                        }
                        KeyCode::Esc => {
                            if state.is_searching {
                                state.is_searching = false;
                                state.search_query.clear();
                                state.backspace_pressed_when_empty = false;
                                update_process_cache(state);
                            } else {
                                state.active_view = None;
                                state.table_scroll_offset = 0;
                                update_process_cache(state);
                            }
                        }
                        KeyCode::Char(' ') => {
                            if state.active_view.is_none() && !state.is_flat_tree && !state.is_searching && !state.flat_rows_cache.is_empty() {
                                let current_pid = state.flat_rows_cache[state.selected_row_index].pid;
                                if state.flat_rows_cache[state.selected_row_index].has_children {
                                    if state.collapsed_pids.contains(&current_pid) {
                                        state.collapsed_pids.remove(&current_pid);
                                    } else {
                                        state.collapsed_pids.insert(current_pid);
                                    }
                                    update_process_cache(state);
                                }
                            }
                        }
                        KeyCode::F(1) => {
                            state.active_view = if state.active_view == Some(1) { None } else { Some(1) };
                        }
                        KeyCode::F(3) => {
                            state.active_view = None;
                            state.is_searching = true;
                            state.backspace_pressed_when_empty = false;
                        }
                        KeyCode::F(5) => {
                            state.active_view = if state.active_view == Some(5) { None } else { Some(5) };
                        }
                        KeyCode::F(6) => {
                            state.active_view = if state.active_view == Some(6) { None } else { Some(6) };
                        }
                        KeyCode::F(7) => {
                            state.active_view = if state.active_view == Some(7) { None } else { Some(7) };
                        }
                        KeyCode::F(8) => {
                            state.active_view = if state.active_view == Some(8) { None } else { Some(8) };
                        }
                        KeyCode::F(9) => {
                            state.active_view = if state.active_view == Some(9) { None } else { Some(9) };
                        }
                        KeyCode::Tab => {
                            if state.active_view.is_none() {
                                state.is_flat_tree = !state.is_flat_tree;
                                update_process_cache(state);
                            } else if state.active_view == Some(8) {
                                state.show_usb_devices = !state.show_usb_devices;
                            } else if state.active_view == Some(7) {
                                state.graph_tab_index = (state.graph_tab_index + 1) % 4;
                            }
                        }
                        KeyCode::Down => {
                            if state.active_view.is_none() && !state.flat_rows_cache.is_empty() {
                                if state.selected_row_index + 1 < state.flat_rows_cache.len() {
                                    state.selected_row_index += 1;
                                }
                            }
                        }
                        KeyCode::Up => {
                            if state.active_view.is_none() {
                                state.selected_row_index = state.selected_row_index.saturating_sub(1);
                            }
                        }
                        KeyCode::Left => {
                            if state.active_view.is_none() {
                                state.table_scroll_offset = state.table_scroll_offset.saturating_sub(1);
                            }
                        }
                        KeyCode::Right => {
                            if state.active_view.is_none() && state.table_scroll_offset < 10 {
                                state.table_scroll_offset += 1;
                            }
                        }
                        KeyCode::PageDown => {
                            if state.active_view.is_none() && !state.flat_rows_cache.is_empty() {
                                state.selected_row_index = (state.selected_row_index + 15)
                                    .min(state.flat_rows_cache.len() - 1);
                            }
                        }
                        KeyCode::PageUp => {
                            if state.active_view.is_none() {
                                state.selected_row_index = state.selected_row_index.saturating_sub(15);
                            }
                        }
                        KeyCode::Char(character) if state.is_searching => {
                            state.search_query.push(character);
                            state.backspace_pressed_when_empty = false;
                            update_process_cache(state);
                        }
                        KeyCode::Backspace if state.is_searching => {
                            if state.search_query.is_empty() {
                                if state.backspace_pressed_when_empty {
                                    state.is_searching = false;
                                    state.backspace_pressed_when_empty = false;
                                    update_process_cache(state);
                                } else {
                                    state.backspace_pressed_when_empty = true;
                                }
                            } else {
                                state.search_query.pop();
                                state.backspace_pressed_when_empty = false;
                                update_process_cache(state);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Event::Mouse(mouse_event) => {
                if state.active_view.is_none() && !state.is_kill_prompt {
                    match mouse_event.kind {
                        MouseEventKind::ScrollDown => {
                            if !state.flat_rows_cache.is_empty()
                                && state.selected_row_index + 1 < state.flat_rows_cache.len()
                            {
                                state.selected_row_index += 1;
                            }
                        }
                        MouseEventKind::ScrollUp => {
                            state.selected_row_index = state.selected_row_index.saturating_sub(1);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn render_active_content(
    frame: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app_state: &ApplicationState,
) {
    match app_state.active_view {
        None => {
            let all_headers = vec![
                "STARTED", "PID", "%MEM", "ELAPSED", "NI", "%CPU", "PGRP", "TT", "RUSER", "EUSER", "FUSER", "COMMAND"
            ];
            let all_widths = vec![
                Constraint::Length(10),
                Constraint::Length(8),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(5),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Min(30),
            ];

            let offset = app_state.table_scroll_offset.min(all_headers.len() - 1);
            let sliced_headers: Vec<&str> = all_headers.iter().skip(offset).cloned().collect();
            let sliced_widths: Vec<Constraint> = all_widths.iter().skip(offset).cloned().collect();

            let table_header = Row::new(sliced_headers)
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .bottom_margin(1);

            let visible_height = area.height.saturating_sub(4) as usize;
            let mut start_idx = 0;
            if app_state.selected_row_index >= start_idx + visible_height && visible_height > 0 {
                start_idx = app_state.selected_row_index - visible_height + 1;
            }

            let mut table_rows = Vec::new();
            for (idx, row_data) in app_state
                .flat_rows_cache
                .iter()
                .enumerate()
                .skip(start_idx)
                .take(visible_height.max(10))
            {
                // Dynamic threshold coloring for CPU usage
                let cpu_color = if row_data.cpu_val >= 70.0 {
                    Color::Red
                } else if row_data.cpu_val >= 30.0 {
                    Color::Yellow
                } else {
                    Color::Green
                };

                let full_row_cells = vec![
                    Cell::from(row_data.started.clone()),
                    Cell::from(row_data.pid_str.clone()),
                    Cell::from(row_data.mem_str.clone()),
                    Cell::from(row_data.elapsed.clone()),
                    Cell::from(row_data.ni.clone()),
                    Cell::from(row_data.cpu_str.clone()).style(Style::default().fg(cpu_color)),
                    Cell::from(row_data.pgrp.clone()),
                    Cell::from(row_data.tt.clone()),
                    Cell::from(row_data.ruser.clone()),
                    Cell::from(row_data.euser.clone()),
                    Cell::from(row_data.fuser.clone()),
                    Cell::from(row_data.display_command.clone()),
                ];

                let sliced_cells: Vec<Cell> = full_row_cells.into_iter().skip(offset).collect();
                let row = Row::new(sliced_cells);

                if idx == app_state.selected_row_index {
                    table_rows.push(row.style(Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)));
                } else {
                    table_rows.push(row);
                }
            }

            let view_label = if app_state.is_searching {
                format!("Search Results [Query: {}]", app_state.search_query)
            } else if app_state.is_flat_tree {
                "Flat Tree View".to_string()
            } else {
                "Process Tree View".to_string()
            };

            let title = format!(" ⚙ sysng: {} [Space: Toggle | Ctrl+K: Signals | Ctrl+H: Help] ", view_label);

            let table = Table::new(table_rows, sliced_widths)
                .header(table_header)
                .block(Block::default().borders(Borders::ALL).title(title));
            frame.render_widget(table, area);

            if app_state.is_kill_prompt && !app_state.flat_rows_cache.is_empty() {
                let selected_proc = &app_state.flat_rows_cache[app_state.selected_row_index];
                
                let mut menu_content = format!(
                    "Send Signal to Process (PID: {}, Name: {})\n\n",
                    selected_proc.pid_str,
                    selected_proc.display_command.trim()
                );

                for (idx, (sig_name, _)) in SIGNAL_LIST.iter().enumerate() {
                    let pointer = if idx == app_state.kill_option_index { "👉 " } else { "   " };
                    menu_content.push_str(&format!("{}{}\n", pointer, sig_name));
                }
                menu_content.push_str("\n[Up/Down] Select | [Enter] Send Signal | [Esc] Cancel");

                let popup_area = centered_rect(60, 40, area);
                let popup_block = Paragraph::new(menu_content)
                    .style(Style::default().fg(Color::White).bg(Color::Black))
                    .block(Block::default().borders(Borders::ALL).title(" Advanced Signal Selection ").style(Style::default().fg(Color::Red)));
                
                frame.render_widget(popup_block, popup_area);
            }

            if let Some((ref msg, _)) = app_state.popup_notification {
                let notification_area = centered_rect(50, 25, area);
                let notification_widget = Paragraph::new(msg.as_str())
                    .style(Style::default().fg(Color::Green).bg(Color::Black))
                    .alignment(ratatui::layout::Alignment::Center)
                    .block(Block::default().borders(Borders::ALL).title(" Success Feedback ").style(Style::default().fg(Color::Green)));
                
                frame.render_widget(notification_widget, notification_area);
            }
        }
        Some(1) => {
            let help_text = " 📖 sysng Help & Documentation (Ctrl+H / F1)\n\n\
   [Esc]            Back to Process View / Clear Search\n\
   [Space]          Collapse/Expand selected tree node\n\
   [Tab]            Toggle Tree / Flat view or switch sub-tabs\n\
   [F3]             Instant Search Filter (Double Backspace on empty exits search)\n\
   [Ctrl+K]         Open Extended Signal Menu for selected process\n\
   [Ctrl+H]         Open/Close this Help screen\n\
   [F5]             System Diagnostics & Information\n\
   [F6]             Top CPU & Memory Resource Consumers\n\
   [F7]             45-Second Resource & Network Graphs\n\
   [F8]             Storage Mounts & USB Devices\n\
   [F9]             Active Network Sockets Inspector\n\
   [Ctrl+Q/C]       Safe Exit Confirmation";
            let p = Paragraph::new(help_text).block(Block::default().borders(Borders::ALL).title(" Help (Ctrl+H) "));
            frame.render_widget(p, area);
        }
        Some(5) => {
            let os_name = System::name().unwrap_or_else(|| "Unknown OS".into());
            let host_name = System::host_name().unwrap_or_else(|| "Unknown Host".into());
            let total_mem = app_state.system_data.total_memory() / 1024 / 1024;
            let used_mem = app_state.system_data.used_memory() / 1024 / 1024;
            let sys_info = format!(" 💻 System Information\n\n   • OS: {}\n   • Hostname: {}\n   • Memory: {} MB / {} MB", os_name, host_name, used_mem, total_mem);
            let p = Paragraph::new(sys_info).block(Block::default().borders(Borders::ALL).title(" System (F5) "));
            frame.render_widget(p, area);
        }
        Some(6) => {
            let mut top_procs: Vec<_> = app_state.system_data.processes().iter().collect();
            top_procs.sort_by(|a, b| b.1.cpu_usage().partial_cmp(&a.1.cpu_usage()).unwrap_or(std::cmp::Ordering::Equal));

            let mut content = String::from(" 📊 Top CPU consuming processes:\n\n");
            for (pid, proc) in top_procs.iter().take(15) {
                let name = proc.name().to_string_lossy();
                let cpu = proc.cpu_usage();
                let mem = proc.memory() / 1024 / 1024;
                content.push_str(&format!("   • PID {:<6} | CPU: {:5.1}% | RAM: {} MB | {}\n", pid, cpu, mem, name));
            }

            let p = Paragraph::new(content).block(Block::default().borders(Borders::ALL).title(" Top Processes (F6) "));
            frame.render_widget(p, area);
        }
        Some(7) => {
            let mut graph_content = String::from(" CPU Usage History (45s window)\n\n");
            for (i, val) in app_state.history.cpu_history.iter().enumerate() {
                let bar_len = ((*val / 100.0) * 40.0) as usize;
                let bar: String = "█".repeat(bar_len.min(40));
                graph_content.push_str(&format!("  [{:02}] {:5.1}% |{}\n", i, val, bar));
            }
            let p = Paragraph::new(graph_content).block(Block::default().borders(Borders::ALL).title(" Graphs (F7) "));
            frame.render_widget(p, area);
        }
        Some(8) => {
            let content = if app_state.show_usb_devices {
                let lsusb = Command::new("lsusb")
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_else(|_| "lsusb unavailable".to_string());
                format!(" USB Devices [Tab to switch]:\n\n{}", lsusb)
            } else {
                let mounts = fs::read_to_string("/proc/mounts").unwrap_or_else(|_| "Mounts unavailable".to_string());
                format!(" Storage Mounts [Tab to switch]:\n\n{}", mounts)
            };
            let p = Paragraph::new(content).block(Block::default().borders(Borders::ALL).title(" Mounts & USB (F8) "));
            frame.render_widget(p, area);
        }
        Some(9) => {
            let sockets = Command::new("ss")
                .arg("-tulpen")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_else(|_| "ss command unavailable".to_string());
            let p = Paragraph::new(sockets).block(Block::default().borders(Borders::ALL).title(" Active Sockets (F9) "));
            frame.render_widget(p, area);
        }
        _ => {
            let p = Paragraph::new("Active View").block(Block::default().borders(Borders::ALL));
            frame.render_widget(p, area);
        }
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: ratatui::layout::Rect) -> ratatui::layout::Rect {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, crossterm::event::EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app_state = initialize_application_state();
    update_process_cache(&mut app_state);

    loop {
        refresh_system_metrics(&mut app_state);

        if let Some((_, instant)) = app_state.popup_notification {
            if instant.elapsed() >= Duration::from_secs(2) {
                app_state.popup_notification = None;
            }
        }

        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(area);

            render_active_content(frame, chunks[0], &app_state);

            let footer_text = if app_state.quit_confirmation {
                "Confirm exit? Press [Y] to quit, [N] or [ESC] to cancel"
            } else if app_state.is_kill_prompt {
                " [UP/DOWN] Choose Signal | [ENTER] Send Signal | [ESC] Cancel "
            } else {
                match app_state.active_view {
                    None => " [UP/DOWN] Select | [SPACE] Toggle | [Ctrl+K] Signals | [Ctrl+H] Help | [F3] Search | [TAB] Tree/Flat ",
                    Some(7) => " [TAB] Switch Graph Metric | [ESC] Back ",
                    Some(8) => " [TAB] Toggle USB/Mounts | [ESC] Back ",
                    _ => " [Ctrl+H] Help | [F3] Search | [F5] Stats | [F6] Top | [F7] Graphs | [F8] Mounts | [F9] Sockets | [ESC] Back ",
                }
            };
            let footer = Paragraph::new(footer_text)
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title(" Quick Actions "));
            frame.render_widget(footer, chunks[1]);
        })?;

        process_events(&mut app_state)?;

        if app_state.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
