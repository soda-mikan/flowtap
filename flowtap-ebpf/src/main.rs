#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        generated::bpf_probe_read_user,
    },
    macros::{kprobe, map, tracepoint, uprobe, uretprobe},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use flowtap_common::{COMM_LEN, Config, Event, EventType, FLAG_TRUNCATED, MAX_PAYLOAD_BYTES};

#[repr(C)]
#[derive(Clone, Copy)]
struct ReadArgs {
    buffer: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    family: u16,
    port: u16,
    addr: u32,
    _padding: [u8; 8],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

// Event contains a 4096-byte payload and must never live on the 512-byte BPF
// stack. A per-CPU slot is safe here because BPF programs do not migrate CPUs.
#[map]
static SCRATCH: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

// SSL_read's entry and return probes can run on different CPUs, so this map is
// keyed by TID rather than being per-CPU.
#[map]
static READ_ARGS: HashMap<u32, ReadArgs> = HashMap::with_max_entries(4096, 0);

#[tracepoint]
pub fn process_exec(ctx: TracePointContext) -> u32 {
    match try_process_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_process_exec(ctx: &TracePointContext) -> Result<(), i64> {
    if !should_trace(ctx) {
        return Ok(());
    }

    let event = begin_event(ctx, EventType::Exec)?;

    // sched_process_exec starts with the common 8-byte tracepoint header. Its
    // first field is __data_loc filename: low 16 bits are the byte offset.
    let data_loc: u32 = unsafe { ctx.read_at(8) }?;
    let filename_offset = (data_loc & 0xffff) as usize;
    if filename_offset < 8 || filename_offset > 4096 {
        return Ok(());
    }

    // The pointer refers to the kernel-owned tracepoint record, hence the
    // kernel-read helper. The helper bounds the copy to Event::detail.
    let filename = unsafe { ctx.as_ptr().add(filename_offset) }.cast::<u8>();
    if let Ok(bytes) = unsafe { bpf_probe_read_kernel_str_bytes(filename, &mut (*event).detail) } {
        unsafe { (*event).detail_len = bytes.len() as u16 };
    }

    output(ctx, event);
    Ok(())
}

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_v4_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_tcp_v4_connect(ctx: &ProbeContext) -> Result<(), i64> {
    if !should_trace(ctx) {
        return Ok(());
    }

    // tcp_v4_connect(struct sock *, struct sockaddr *, int) receives a
    // kernel-copied sockaddr. It is not a user-space pointer at this hook.
    let address: *const SockAddrIn = ctx.arg(1).ok_or(1i64)?;
    let address = unsafe { bpf_probe_read_kernel(address) }?;
    if address.family != 2 {
        return Ok(());
    }

    let event = begin_event(ctx, EventType::Connect)?;
    unsafe {
        (*event).addr_v4 = address.addr;
        (*event).port = u16::from_be(address.port);
    }
    output(ctx, event);
    Ok(())
}

#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    match try_ssl_write(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_write(ctx: &ProbeContext) -> Result<(), i64> {
    if !should_trace(ctx) {
        return Ok(());
    }

    let buffer: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let raw_length: u64 = ctx.arg(2).ok_or(1i64)?;
    let Some(length) = positive_openssl_length(raw_length) else {
        return Ok(());
    };
    if buffer.is_null() {
        return Ok(());
    }

    emit_tls(ctx, EventType::TlsWrite, buffer, length)
}

#[uprobe]
pub fn ssl_read_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_read_enter(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_enter(ctx: &ProbeContext) -> Result<(), i64> {
    if !should_trace(ctx) {
        return Ok(());
    }

    let buffer: *const u8 = ctx.arg(1).ok_or(1i64)?;
    if buffer.is_null() {
        return Ok(());
    }

    READ_ARGS
        .insert(
            &ctx.pid(),
            &ReadArgs {
                buffer: buffer as u64,
            },
            0,
        )
        .map_err(|error| error as i64)?;
    Ok(())
}

#[uretprobe]
pub fn ssl_read_return(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_return(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_return(ctx: &RetProbeContext) -> Result<(), i64> {
    let tid = ctx.pid();
    let Some(args_ptr) = READ_ARGS.get_ptr(&tid) else {
        return Ok(());
    };

    // Copy the map value before removing it; dereferencing it after removal
    // would be invalid because the kernel may immediately reuse that storage.
    let args = unsafe { args_ptr.read() };
    let _ = READ_ARGS.remove(&tid);

    let raw_length = ctx.ret::<u64>();
    let Some(length) = positive_openssl_length(raw_length) else {
        return Ok(());
    };
    if !should_trace(ctx) {
        return Ok(());
    }

    emit_tls(ctx, EventType::TlsRead, args.buffer as *const u8, length)
}

#[inline(always)]
fn positive_openssl_length(raw_length: u64) -> Option<u64> {
    // OpenSSL exposes these lengths as signed 32-bit ints, but uprobe
    // registers are 64-bit and their upper half is not verifier-bounded.
    // Reject negative/zero low halves and explicitly mask the accepted value
    // so helper size arguments have a non-negative 64-bit range.
    if raw_length & (1u64 << 31) != 0 {
        return None;
    }
    let length = raw_length & i32::MAX as u64;
    if length == 0 { None } else { Some(length) }
}

#[inline(always)]
fn should_trace<C: EbpfContext>(ctx: &C) -> bool {
    let Some(config_ptr) = CONFIG.get_ptr(0) else {
        return false;
    };
    let config = unsafe { config_ptr.read() };

    if config.target_pid != 0 && config.target_pid != ctx.tgid() {
        return false;
    }
    if config.filter_comm_enabled == 0 {
        return true;
    }

    let Ok(comm) = ctx.command() else {
        return false;
    };
    let mut index = 0;
    while index < COMM_LEN {
        if comm[index] != config.filter_comm[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[inline(always)]
fn begin_event<C: EbpfContext>(ctx: &C, kind: EventType) -> Result<*mut Event, i64> {
    let event = SCRATCH.get_ptr_mut(0).ok_or(1i64)?;

    // SCRATCH is per-CPU map memory, not the BPF stack. The pointer is valid
    // for this invocation and there is no concurrent writer on this CPU.
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).pid = ctx.tgid();
        (*event).tid = ctx.pid();
        (*event).payload_len = 0;
        (*event).detail_len = 0;
        (*event).port = 0;
        (*event).addr_v4 = 0;
        (*event).event_type = kind as u8;
        (*event).flags = 0;
        (*event)._padding = [0; 2];
        (*event).comm = ctx.command().unwrap_or([0; COMM_LEN]);
    }
    Ok(event)
}

#[inline(always)]
fn emit_tls<C: EbpfContext>(
    ctx: &C,
    kind: EventType,
    buffer: *const u8,
    supplied_length: u64,
) -> Result<(), i64> {
    // BPF helpers receive arguments in 64-bit registers. Keep the bounds
    // calculation 64-bit so older verifiers retain the zero-extended range
    // when this value is passed as bpf_probe_read_user's size argument.
    let mut capture_length = supplied_length;
    let Some(config_ptr) = CONFIG.get_ptr(0) else {
        return Err(1);
    };
    let max_configured = unsafe { (*config_ptr).max_payload_bytes as u64 };

    if capture_length > max_configured {
        capture_length = max_configured;
    }
    if capture_length > MAX_PAYLOAD_BYTES as u64 {
        capture_length = MAX_PAYLOAD_BYTES as u64;
    }
    if capture_length == 0 {
        return Ok(());
    }

    let event = begin_event(ctx, kind)?;
    unsafe {
        (*event).payload_len = capture_length as u32;
        if supplied_length > capture_length {
            (*event).flags |= FLAG_TRUNCATED;
        }
    }

    // OpenSSL owns `buffer`, so it must be accessed with the user-memory
    // helper. The destination is the verifier-visible bounded map value.
    let result = unsafe {
        bpf_probe_read_user(
            (*event).payload.as_mut_ptr().cast::<c_void>(),
            capture_length as u32,
            buffer.cast::<c_void>(),
        )
    };
    if result < 0 {
        return Err(result);
    }

    output(ctx, event);
    Ok(())
}

#[inline(always)]
fn output<C: EbpfContext>(ctx: &C, event: *mut Event) {
    // event points into SCRATCH and remains valid until this BPF invocation
    // returns. RingBuf::output copies the bytes synchronously.
    let _ = ctx;
    let _ = EVENTS.output::<Event>(unsafe { &*event }, 0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
