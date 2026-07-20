mod output;
mod redact;

use std::{
    mem,
    path::{Path, PathBuf},
    ptr,
};

use anyhow::{Context as _, bail};
use aya::{
    Ebpf,
    maps::{Array, RingBuf},
    programs::{KProbe, TracePoint, UProbe, uprobe::UProbeScope},
};
use clap::Parser;
use flowtap_common::{COMM_LEN, Config, Event};
use output::Processor;
use tokio::{io::unix::AsyncFd, signal};

#[derive(Debug, Parser)]
#[command(
    name = "flowtap",
    version,
    about = "Observe process execs, IPv4 TCP connects, and optional OpenSSL plaintext"
)]
struct Args {
    /// Emit one JSON object per line.
    #[arg(long)]
    json: bool,

    /// Only observe this process ID.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pid: Option<u32>,

    /// Only observe this Linux task command name (maximum 15 bytes).
    #[arg(long)]
    comm: Option<String>,

    /// EXPERIMENTAL: capture plaintext at OpenSSL SSL_write/SSL_read.
    #[arg(long)]
    tls_plaintext: bool,

    /// Allow TLS plaintext capture from every process using the selected libssl.
    #[arg(
        long,
        requires = "tls_plaintext",
        conflicts_with_all = ["pid", "comm"]
    )]
    all_processes: bool,

    /// Exact path to the libssl shared object used by the target process.
    #[arg(long, requires = "tls_plaintext")]
    libssl_path: Option<PathBuf>,

    /// Maximum bytes captured from each TLS buffer.
    #[arg(
        long,
        default_value_t = 128,
        value_parser = clap::value_parser!(u32).range(1..=4096)
    )]
    max_payload_bytes: u32,

    /// Mask common HTTP credential and cookie header values.
    #[arg(long, requires = "tls_plaintext")]
    redact: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    validate_args(&args)?;
    warn_about_unscoped_tls(&args);
    raise_memlock_limit();

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/flowtap"
    )))
    .context("load embedded eBPF object")?;

    write_config(&mut ebpf, &args)?;
    attach_core_programs(&mut ebpf)?;
    if args.tls_plaintext {
        attach_tls_programs(
            &mut ebpf,
            args.libssl_path.as_ref().expect("validated --libssl-path"),
        )?;
    }

    let ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .context("eBPF map EVENTS is missing")?,
    )
    .context("open EVENTS ring buffer")?;
    let mut ring = AsyncFd::new(ring).context("register EVENTS ring buffer with epoll")?;

    let mut processor = Processor::new(args.json, args.redact);
    processor.print_header();

    let interrupt = signal::ctrl_c();
    tokio::pin!(interrupt);
    loop {
        tokio::select! {
            result = &mut interrupt => {
                result.context("wait for Ctrl-C")?;
                break;
            }
            ready = ring.readable_mut() => {
                let mut guard = ready.context("wait for ring buffer data")?;
                while let Some(bytes) = guard.get_inner_mut().next() {
                    if let Some(event) = decode_event(&bytes) {
                        processor.process(event);
                    } else {
                        eprintln!(
                            "ignored event with size {}, expected {}",
                            bytes.len(),
                            mem::size_of::<Event>()
                        );
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}

fn validate_args(args: &Args) -> anyhow::Result<()> {
    if args.tls_plaintext {
        if args.pid.is_none() && args.comm.is_none() && !args.all_processes {
            bail!(
                "--tls-plaintext requires --pid <PID> or --comm <NAME>; pass \
                 --all-processes only for intentional system-wide plaintext capture"
            );
        }
        let path = args
            .libssl_path
            .as_ref()
            .context("--tls-plaintext requires --libssl-path <PATH>")?;
        if !path.is_file() {
            bail!("libssl path is not a regular file: {}", path.display());
        }
    }

    if let Some(comm) = &args.comm {
        if comm.is_empty() {
            bail!("--comm must not be empty");
        }
        if comm.len() >= COMM_LEN {
            bail!("--comm must be at most {} bytes", COMM_LEN - 1);
        }
        if comm.as_bytes().contains(&0) {
            bail!("--comm must not contain a NUL byte");
        }
    }
    Ok(())
}

fn warn_about_unscoped_tls(args: &Args) {
    if args.tls_plaintext && args.all_processes {
        eprintln!(
            "warning: --all-processes captures OpenSSL plaintext from every process using the \
             selected libssl; output may contain credentials, cookies, or personal data"
        );
    }
}

fn write_config(ebpf: &mut Ebpf, args: &Args) -> anyhow::Result<()> {
    let mut config = Config::empty();
    config.max_payload_bytes = args.max_payload_bytes;
    config.target_pid = args.pid.unwrap_or(0);
    if let Some(comm) = &args.comm {
        config.filter_comm[..comm.len()].copy_from_slice(comm.as_bytes());
        config.filter_comm_enabled = 1;
    }

    let map = ebpf
        .map_mut("CONFIG")
        .context("eBPF map CONFIG is missing")?;
    let mut map = Array::<_, Config>::try_from(map).context("open CONFIG map")?;
    map.set(0, config, 0).context("write CONFIG map")
}

fn attach_core_programs(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let exec: &mut TracePoint = ebpf
        .program_mut("process_exec")
        .context("eBPF program process_exec is missing")?
        .try_into()?;
    exec.load().context("load process_exec")?;
    exec.attach("sched", "sched_process_exec")
        .context("attach sched/sched_process_exec")?;

    let connect: &mut KProbe = ebpf
        .program_mut("tcp_v4_connect")
        .context("eBPF program tcp_v4_connect is missing")?
        .try_into()?;
    connect.load().context("load tcp_v4_connect")?;
    connect
        .attach("tcp_v4_connect", 0)
        .context("attach kprobe tcp_v4_connect")?;
    Ok(())
}

fn attach_tls_programs(ebpf: &mut Ebpf, libssl_path: &Path) -> anyhow::Result<()> {
    attach_uprobe(
        ebpf,
        "ssl_write",
        "SSL_write",
        libssl_path,
        "attach uprobe SSL_write",
    )?;
    attach_uprobe(
        ebpf,
        "ssl_read_enter",
        "SSL_read",
        libssl_path,
        "attach uprobe SSL_read",
    )?;
    attach_uprobe(
        ebpf,
        "ssl_read_return",
        "SSL_read",
        libssl_path,
        "attach uretprobe SSL_read",
    )?;
    Ok(())
}

fn attach_uprobe(
    ebpf: &mut Ebpf,
    program_name: &str,
    symbol: &str,
    target: &Path,
    context: &str,
) -> anyhow::Result<()> {
    let program: &mut UProbe = ebpf
        .program_mut(program_name)
        .with_context(|| format!("eBPF program {program_name} is missing"))?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("load {program_name}"))?;
    program
        .attach(symbol, target, UProbeScope::AllProcesses)
        .with_context(|| context.to_owned())?;
    Ok(())
}

fn decode_event(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < mem::size_of::<Event>() {
        return None;
    }
    // Event is repr(C), Copy, and consists only of integer/byte fields. Ring
    // buffer records do not guarantee Rust alignment, so read_unaligned is required.
    Some(unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<Event>()) })
}

fn raise_memlock_limit() {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // setrlimit receives a valid pointer to an initialized rlimit and does not
    // retain it. Failure is non-fatal on kernels using memcg BPF accounting.
    let result = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if result != 0 {
        eprintln!(
            "warning: could not raise RLIMIT_MEMLOCK: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls_args() -> Args {
        Args {
            json: false,
            pid: None,
            comm: None,
            tls_plaintext: true,
            all_processes: false,
            libssl_path: Some(std::env::current_exe().expect("current test executable")),
            max_payload_bytes: 128,
            redact: false,
        }
    }

    #[test]
    fn tls_plaintext_requires_an_explicit_scope() {
        let error = validate_args(&tls_args()).expect_err("unscoped TLS must be rejected");
        assert!(error.to_string().contains("--all-processes"));
    }

    #[test]
    fn tls_plaintext_accepts_a_pid_scope() {
        let mut args = tls_args();
        args.pid = Some(42);
        validate_args(&args).expect("PID-scoped TLS should be accepted");
    }

    #[test]
    fn tls_plaintext_accepts_a_comm_scope() {
        let mut args = tls_args();
        args.comm = Some("curl".to_owned());
        validate_args(&args).expect("comm-scoped TLS should be accepted");
    }

    #[test]
    fn tls_plaintext_accepts_explicit_all_processes() {
        let mut args = tls_args();
        args.all_processes = true;
        validate_args(&args).expect("explicit system-wide TLS should be accepted");
    }

    #[test]
    fn all_processes_requires_tls_plaintext() {
        let result = Args::try_parse_from(["flowtap", "--all-processes"]);
        assert!(result.is_err());
    }

    #[test]
    fn all_processes_conflicts_with_process_filters() {
        let result = Args::try_parse_from([
            "flowtap",
            "--tls-plaintext",
            "--libssl-path",
            "/tmp/libssl.so",
            "--pid",
            "42",
            "--all-processes",
        ]);
        assert!(result.is_err());
    }
}
