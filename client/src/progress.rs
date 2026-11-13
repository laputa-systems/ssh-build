use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::time::{Duration, Instant};

use rustix::termios::isatty;

use crate::copy::Progress;
use crate::terminal::terminal_size;

const REDRAW_EVERY: Duration = Duration::from_millis(100);
const MINIMUM_WIDTH: usize = 40;

/// A progress meter that draws only when its output is a terminal.
///
/// Warnings always print, on the meter's stream, after the meter line is cleared.
pub struct Meter {
    out: Option<OwnedFd>,
    label: String,
    size: Option<u64>,
    started: Instant,
    drawn: Option<Instant>,
    done: u64,
    columns: usize,
}

impl Meter {
    /// Draw on a duplicate of `stream` when it is a terminal, and stay silent otherwise.
    pub fn new(stream: impl AsFd) -> Self {
        let out = isatty(&stream)
            .then(|| stream.as_fd().try_clone_to_owned().ok())
            .flatten();
        Self {
            out,
            label: String::new(),
            size: None,
            started: Instant::now(),
            drawn: None,
            done: 0,
            columns: 80,
        }
    }

    /// Whether the meter draws.
    pub fn active(&self) -> bool {
        self.out.is_some()
    }

    fn draw(&mut self, last: bool) {
        let Some(out) = self.out.as_ref() else {
            return;
        };
        self.columns = terminal_size(out).cols as usize;
        let elapsed = self.started.elapsed().as_secs_f64().max(0.001);
        let rate = self.done as f64 / elapsed;
        let percent = match self.size {
            Some(size) if size > 0 => format!("{:3}%", (self.done.saturating_mul(100) / size).min(100)),
            _ => "    ".to_owned(),
        };
        let eta = match self.size {
            Some(size) if size > self.done && rate > 0.0 && !last => {
                format_time(((size - self.done) as f64 / rate) as u64)
            }
            _ => format_time(elapsed as u64),
        };
        let stats = format!(" {percent} {:>9} {:>11} {eta}", human(self.done), format!("{}/s", human(rate as u64)));
        let width = self.columns.max(MINIMUM_WIDTH);
        let room = width.saturating_sub(stats.chars().count() + 1);
        let name: String = if self.label.chars().count() > room {
            self.label.chars().take(room.saturating_sub(1)).collect::<String>() + "~"
        } else {
            self.label.clone()
        };
        let line = format!("\r{name:<room$}{stats}");
        let mut file = std::fs::File::from(match out.try_clone() {
            Ok(file) => file,
            Err(_) => return,
        });
        let _ = file.write_all(line.as_bytes());
        if last {
            let _ = file.write_all(b"\n");
        }
        let _ = file.flush();
        self.drawn = Some(Instant::now());
    }
}

impl Progress for Meter {
    fn file_start(&mut self, name: &str, size: Option<u64>) {
        self.label = name.to_owned();
        self.size = size;
        self.done = 0;
        self.started = Instant::now();
        self.drawn = None;
        self.draw(false);
    }

    fn file_advance(&mut self, done: u64) {
        self.done = done;
        if self.drawn.is_none_or(|at| at.elapsed() >= REDRAW_EVERY) {
            self.draw(false);
        }
    }

    fn file_end(&mut self) {
        self.draw(true);
    }

    fn warn(&mut self, message: &str) {
        if let Some(out) = self.out.as_ref()
            && let Ok(copy) = out.try_clone()
        {
            let mut file = std::fs::File::from(copy);
            let _ = file.write_all(b"\r\x1b[K");
        }
        eprintln!("{message}");
    }
}

/// Format a byte count the way `ls -h` does, with one decimal below ten units.
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes}{}", UNITS[0])
    } else if value < 10.0 {
        format!("{value:.1}{}", UNITS[unit])
    } else {
        format!("{value:.0}{}", UNITS[unit])
    }
}

fn format_time(seconds: u64) -> String {
    if seconds >= 3600 {
        format!("{}:{:02}:{:02}", seconds / 3600, seconds / 60 % 60, seconds % 60)
    } else {
        format!("{:02}:{:02}", seconds / 60, seconds % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_human_readable() {
        assert_eq!(human(0), "0B");
        assert_eq!(human(1023), "1023B");
        assert_eq!(human(1024), "1.0KB");
        assert_eq!(human(10 * 1024 * 1024), "10MB");
        assert_eq!(human(1536 * 1024), "1.5MB");
    }

    #[test]
    fn times_are_clock_formatted() {
        assert_eq!(format_time(5), "00:05");
        assert_eq!(format_time(3725), "1:02:05");
    }

    #[test]
    fn a_pipe_gets_no_meter() {
        let (reader, writer) = rustix::pipe::pipe().expect("pipe");
        drop(reader);
        assert!(!Meter::new(writer).active());
    }
}
