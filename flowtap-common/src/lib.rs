#![no_std]

pub const COMM_LEN: usize = 16;
pub const EXEC_DETAIL_LEN: usize = 256;
pub const MAX_PAYLOAD_BYTES: usize = 4096;

pub const FLAG_TRUNCATED: u8 = 1;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventType {
    Exec = 1,
    Connect = 2,
    TlsWrite = 3,
    TlsRead = 4,
}

impl EventType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Exec),
            2 => Some(Self::Connect),
            3 => Some(Self::TlsWrite),
            4 => Some(Self::TlsRead),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "EXEC",
            Self::Connect => "CONNECT",
            Self::TlsWrite => "TLS_WRITE",
            Self::TlsRead => "TLS_READ",
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub timestamp_ns: u64,
    /// Thread-group ID: this is the process ID seen from user space.
    pub pid: u32,
    /// Kernel PID: this is the thread ID seen from user space.
    pub tid: u32,
    pub payload_len: u32,
    pub detail_len: u16,
    pub port: u16,
    pub addr_v4: u32,
    pub event_type: u8,
    pub flags: u8,
    pub _padding: [u8; 2],
    pub comm: [u8; COMM_LEN],
    pub detail: [u8; EXEC_DETAIL_LEN],
    pub payload: [u8; MAX_PAYLOAD_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub max_payload_bytes: u32,
    pub target_pid: u32,
    pub filter_comm: [u8; COMM_LEN],
    pub filter_comm_enabled: u8,
    pub _padding: [u8; 3],
}

impl Config {
    pub const fn empty() -> Self {
        Self {
            max_payload_bytes: 128,
            target_pid: 0,
            filter_comm: [0; COMM_LEN],
            filter_comm_enabled: 0,
            _padding: [0; 3],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}
