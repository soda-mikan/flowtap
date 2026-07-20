use std::{
    collections::HashMap,
    fs,
    net::Ipv4Addr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Local, SecondsFormat};
use flowtap_common::{Event, EventType, FLAG_TRUNCATED};
use serde::Serialize;

use crate::redact::redact_http_headers;

#[derive(Clone)]
struct ProcessInfo {
    comm: String,
    command: String,
}

pub struct Processor {
    json: bool,
    redact: bool,
    clock: WallClock,
    processes: HashMap<u32, ProcessInfo>,
}

impl Processor {
    pub fn new(json: bool, redact: bool) -> Self {
        Self {
            json,
            redact,
            clock: WallClock::new(),
            processes: HashMap::new(),
        }
    }

    pub fn print_header(&self) {
        if !self.json {
            println!(
                "{:<32} {:<7} {:<15} {:<11} DETAIL",
                "TIME", "PID", "COMM", "EVENT"
            );
        }
    }

    pub fn process(&mut self, event: Event) {
        let Some(kind) = EventType::from_u8(event.event_type) else {
            return;
        };

        let timestamp = self.clock.format(event.timestamp_ns);
        let event_comm = nul_terminated(&event.comm);
        let truncated = event.flags & FLAG_TRUNCATED != 0;

        let (comm, detail, correlated_exec) = match kind {
            EventType::Exec => {
                let filename = utf8_lossy(&event.detail, event.detail_len as usize);
                let command = read_cmdline(event.pid)
                    .filter(|value| !value.is_empty())
                    .unwrap_or(filename);
                self.processes.insert(
                    event.pid,
                    ProcessInfo {
                        comm: event_comm.clone(),
                        command: command.clone(),
                    },
                );
                (event_comm, command.clone(), Some(command))
            }
            EventType::Connect => {
                let process = self.processes.get(&event.pid);
                let comm = process
                    .map(|value| value.comm.clone())
                    .filter(|value| !value.is_empty())
                    .unwrap_or(event_comm);
                let address = Ipv4Addr::from(u32::from_be(event.addr_v4));
                let detail = format!("{address}:{}", event.port);
                let correlated = process.map(|value| value.command.clone());
                (comm, detail, correlated)
            }
            EventType::TlsWrite | EventType::TlsRead => {
                let process = self.processes.get(&event.pid);
                let comm = process
                    .map(|value| value.comm.clone())
                    .filter(|value| !value.is_empty())
                    .unwrap_or(event_comm);
                let payload_length = (event.payload_len as usize).min(event.payload.len());
                let raw = String::from_utf8_lossy(&event.payload[..payload_length]).into_owned();
                let mut detail = if self.redact {
                    redact_http_headers(&raw)
                } else {
                    raw
                };
                if truncated {
                    detail.push('…');
                }
                let correlated = process.map(|value| value.command.clone());
                (comm, detail, correlated)
            }
        };

        if self.json {
            let line = JsonEvent {
                time: timestamp,
                pid: event.pid,
                tid: event.tid,
                comm,
                event: kind.as_str(),
                detail,
                correlated_exec,
                truncated,
            };
            match serde_json::to_string(&line) {
                Ok(json) => println!("{json}"),
                Err(error) => eprintln!("failed to serialize event: {error}"),
            }
        } else {
            let comm = escape_table_field(&comm);
            println!(
                "{:<32} {:<7} {:<15} {:<11} {}",
                timestamp,
                event.pid,
                comm,
                kind.as_str(),
                escape_table_field(&detail)
            );
        }
    }
}

#[derive(Serialize)]
struct JsonEvent {
    time: String,
    pid: u32,
    tid: u32,
    comm: String,
    event: &'static str,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    correlated_exec: Option<String>,
    truncated: bool,
}

struct WallClock {
    monotonic_origin: SystemTime,
}

impl WallClock {
    fn new() -> Self {
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // clock_gettime only initializes a plain timespec. CLOCK_MONOTONIC is
        // the same time base used by bpf_ktime_get_ns.
        let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
        let monotonic = if result == 0 && now.tv_sec >= 0 && now.tv_nsec >= 0 {
            Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
        } else {
            Duration::ZERO
        };
        let monotonic_origin = SystemTime::now()
            .checked_sub(monotonic)
            .unwrap_or(UNIX_EPOCH);
        Self { monotonic_origin }
    }

    fn format(&self, timestamp_ns: u64) -> String {
        let time = self
            .monotonic_origin
            .checked_add(Duration::from_nanos(timestamp_ns))
            .unwrap_or(UNIX_EPOCH);
        let local: DateTime<Local> = time.into();
        local.to_rfc3339_opts(SecondsFormat::Millis, false)
    }
}

fn read_cmdline(pid: u32) -> Option<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let arguments = bytes
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| String::from_utf8_lossy(argument))
        .collect::<Vec<_>>();
    Some(
        arguments
            .iter()
            .map(|value| value.as_ref())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn nul_terminated(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn utf8_lossy(bytes: &[u8], requested_length: usize) -> String {
    let length = requested_length.min(bytes.len());
    let end = bytes[..length]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(length);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn escape_table_field(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\r' => escaped.push_str("\\r"),
            '\n' => escaped.push_str("\\n"),
            '\t' => escaped.push_str("\\t"),
            '\0' => escaped.push_str("\\0"),
            character if character.is_control() => escaped.extend(character.escape_default()),
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::escape_table_field;

    #[test]
    fn table_output_escapes_control_characters() {
        assert_eq!(
            escape_table_field("a\r\nb\t\0\\\u{1b}\u{7f}"),
            "a\\r\\nb\\t\\0\\\\\\u{1b}\\u{7f}"
        );
    }

    #[test]
    fn table_output_contains_no_literal_control_characters() {
        let escaped = escape_table_field("\u{1b}]0;title\u{7}text");
        assert!(escaped.chars().all(|character| !character.is_control()));
    }
}
