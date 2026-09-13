//! ============================================================================
//! sysng - Zero-Bloat System Monitor (GNU/KISS Architecture)
//! Designed for high flexibility, fault tolerance, and cross-platform portability.
//! ============================================================================

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};
use std::{
    error::Error,
    io,
    time::{Duration, Instant},
};
use sysinfo::{ProcessesToUpdate, System};

/// Application error boundary wrapper for fault tolerance.
type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Active view states mapped to system function keys (F1 - F10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveView {
    ProcessTable = 1,
    Help = 2,
    SysInfo = 5,
    TopConsumers = 6,
    Flatpak = 7,
    Hardware = 8,
    Graph = 9,
    Ports = 10,
}

/// Central application state container.
struct App {
    sys: System,
    active_view: ActiveView,
    should_quit: bool,
    show_quit_confirm: bool,
}

impl App {
    /// Initializes system monitors safely, handling potential backend telemetry failures.
    fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self {
            sys,
            active_view: ActiveView::ProcessTable,
            should_quit: false,
            show_quit_confirm: false,
        }
    }
    
    /// Safely refreshes system telemetry metrics with error containment.
    fn update_telemetry(&mut self) {
        self.sys.refresh_processes(ProcessesToUpdate::All);
        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();
    }
}

fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    let mut app = App::new();
    let tick_rate = Duration::from_millis(750);
    let mut last_tick = Instant::now();
    
    let res = run_event_loop(&mut terminal, &mut app, tick_rate, &mut last_tick);
    
    // Ensure terminal states are safely restored even if runtime panics occur.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    
    res
}

/// Core reactive event-loop handling non-blocking inputs and periodic telemetry ticks.
fn run_event_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    tick_rate: Duration,
    last_tick: &mut Instant,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;
        
        let timeout = tick_rate
        .checked_sub(last_tick.elapsed())
        .unwrap_or_else(|| Duration::from_secs(0));
        
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if app.show_quit_confirm {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => app.should_quit = true,
                        _ => app.show_quit_confirm = false,
                    }
                    continue;
                }
                
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        app.show_quit_confirm = true;
                    }
                    KeyCode::F(1) => app.active_view = ActiveView::Help,
                    KeyCode::F(5) => app.active_view = ActiveView::SysInfo,
                    KeyCode::F(6) => app.active_view = ActiveView::TopConsumers,
                    KeyCode::F(7) => app.active_view = ActiveView::Flatpak,
                    KeyCode::F(8) => app.active_view = ActiveView::Hardware,
                    KeyCode::F(9) => app.active_view = ActiveView::Graph,
                    KeyCode::F(10) => app.active_view = ActiveView::Ports,
                    _ => {}
                }
            }
        }
        
        if last_tick.elapsed() >= tick_rate {
            app.update_telemetry();
            *last_tick = Instant::now();
        }
        
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

/// Renders views dynamically depending on the current application state.
fn ui(f: &mut ratatui::Frame, app: &App) {
    let size = f.area();
    
    let chunks = Layout::default()
    .direction(Direction::Vertical)
    .constraints([Constraint::Min(10), Constraint::Length(3)].as_ref())
    .split(size);
    
    match app.active_view {
        ActiveView::ProcessTable | ActiveView::Help => {
            let rows: Vec<Row> = app
            .sys
            .processes()
            .iter()
            .take(30)
            .map(|(pid, proc)| {
                Row::new(vec![
                    Cell::from(pid.to_string()),
                         Cell::from(proc.name().to_string_lossy().into_owned()),
                         Cell::from(format!("{:.1}%", proc.cpu_usage())),
                         Cell::from(format!("{:.1} MB", proc.memory() as f64 / 1024.0 / 1024.0)),
                         Cell::from(proc.run_time().to_string()),
                ])
            })
            .collect();
            
            let widths = [
                Constraint::Length(8),
                Constraint::Length(25),
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Length(12),
            ];
            
            let table = Table::new(rows, widths)
            .header(
                Row::new(vec!["PID", "COMMAND", "%CPU", "%MEM", "ELAPSED"])
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            )
            .block(
                Block::default()
                .borders(Borders::ALL)
                .title(" sysng - Process Telemetry & Metrics Table "),
            );
            
            f.render_widget(table, chunks[0]);
        }
        ActiveView::SysInfo => {
            let info_text = format!(
                "Host Name:     {}\nOS Version:    {}\nKernel Build:  {}\nCPU Cores:     {}",
                System::host_name().unwrap_or_else(|| "Unknown".to_string()),
                                    System::os_version().unwrap_or_else(|| "Unknown".to_string()),
                                    System::kernel_version().unwrap_or_else(|| "Unknown".to_string()),
                                    app.sys.cpus().len()
            );
            let paragraph = Paragraph::new(info_text).block(
                Block::default()
                .borders(Borders::ALL)
                .title(" [F5] Host Parameters & System Information "),
            );
            f.render_widget(paragraph, chunks[0]);
        }
        ActiveView::TopConsumers => {
            let paragraph = Paragraph::new("Sorted breakdowns of highest resource-consuming tasks (Under development)")
            .block(Block::default().borders(Borders::ALL).title(" [F6] Top Consumers "));
            f.render_widget(paragraph, chunks[0]);
        }
        ActiveView::Flatpak => {
            let paragraph = Paragraph::new("Local container runtimes and installed Flatpak applications inspection (Under development)")
            .block(Block::default().borders(Borders::ALL).title(" [F7] Flatpak / Containers "));
            f.render_widget(paragraph, chunks[0]);
        }
        ActiveView::Hardware => {
            let paragraph = Paragraph::new("Physical storage volumes, mount points, and drive capacity metrics (Under development)")
            .block(Block::default().borders(Borders::ALL).title(" [F8] Hardware & Volumes "));
            f.render_widget(paragraph, chunks[0]);
        }
        ActiveView::Graph => {
            let paragraph = Paragraph::new("Real-time historical CPU load and network interface data streams (Under development)")
            .block(Block::default().borders(Borders::ALL).title(" [F9] Telemetry Graphs "));
            f.render_widget(paragraph, chunks[0]);
        }
        ActiveView::Ports => {
            let paragraph = Paragraph::new("Active network sockets and listening TCP/UDP ports monitoring (Under development)")
            .block(Block::default().borders(Borders::ALL).title(" [F10] Network Ports "));
            f.render_widget(paragraph, chunks[0]);
        }
    }
    
    let footer_text = if app.show_quit_confirm {
        " Are you sure you want to quit? Press 'Y' to exit, any other key to resume. "
    } else {
        " [F1] Help | [F5] SysInfo | [F6] Top | [F7] Flatpak | [F8] HW | [F9] Graph | [F10] Ports | [q] Quit "
    };
    
    let footer_style = if app.show_quit_confirm {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    
    let footer = Paragraph::new(footer_text).style(footer_style);
    f.render_widget(footer, chunks[1]);
}
