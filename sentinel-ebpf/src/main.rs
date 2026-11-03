#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes, bpf_probe_read_user_buf
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use sentinel_common::{ExecEvent, OpenatEvent, ConnectEvent};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
pub const EVENT_EXEC: u32 = 1;
pub const EVENT_OPENAT: u32 = 2;
pub const EVENT_CONNECT: u32 = 3;

#[tracepoint]
pub fn sentinel(ctx: TracePointContext) -> u32 {
    match run_all(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn run_all(ctx: TracePointContext) -> Result<(), i64> {
    // try_execve(&ctx)?;
    // try_openAt(&ctx)?;
    try_connect(&ctx)?;
    Ok(())
}

fn try_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let filename_ptr = unsafe { ctx.read_at::<u64>(16)? } as *const u8;

    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        let ev = unsafe { &mut *entry.as_mut_ptr() };
        ev.kind = EVENT_EXEC;
        ev.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        ev.uid = bpf_get_current_uid_gid() as u32;
        ev.comm = bpf_get_current_comm().unwrap_or([0; 16]);
        ev.filename = [0; 256];
        unsafe {
            let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut ev.filename);
        }
        entry.submit(0);
    }
    Ok(())
}

fn try_openAt(ctx: &TracePointContext) -> Result<(), i64> {
    let filename_ptr = unsafe { ctx.read_at::<u64>(16)? } as *const u8;
    let dfd: i32 = unsafe { ctx.read_at(16)? };
    let flags: u32 = unsafe { ctx.read_at(32)? };
    let mode: u32 = unsafe { ctx.read_at(36)? };
    if let Some(mut entry) = EVENTS.reserve::<OpenatEvent>(0) {
        let ev = unsafe {&mut *entry.as_mut_ptr()};
        ev.kind = EVENT_OPENAT;
        ev.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        ev.dfd = dfd;
        ev.flags = flags;
        ev.mode = mode;
        ev.filename = [0; 256];
        unsafe {
            let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut ev.filename);
        }
        entry.submit(0);
    }
    Ok(())

}

fn try_connect(ctx: &TracePointContext) -> Result<(), i64> {
    let fd: i32 = unsafe { ctx.read_at(16)? };
    let uservaddr = unsafe { ctx.read_at::<u64>(24)? } as *const u8;
    let addrlen: u32 = unsafe { ctx.read_at(32)? };

    let mut sa = [0u8; 8];
    unsafe { bpf_probe_read_user_buf(uservaddr, &mut sa)? };
    let family = u16::from_ne_bytes([sa[0], sa[1]]);

    if family != 2 && family != 10 {
        return Ok(());
    }

    let mut addr = [0u8; 16];
    if family == 2 {
        addr[0] = sa[4];
        addr[1] = sa[5];
        addr[2] = sa[6];
        addr[3] = sa[7];
    } else if addrlen >= 24 {
        unsafe { bpf_probe_read_user_buf(uservaddr.add(8), &mut addr)? };
    }

    if let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) {
        let ev = unsafe { &mut *entry.as_mut_ptr() };
        ev.kind = EVENT_CONNECT;
        ev.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        ev.uid = bpf_get_current_uid_gid() as u32;
        ev.fd = fd;
        ev.comm = bpf_get_current_comm().unwrap_or([0; 16]);
        ev.family = family;
        ev.port = u16::from_ne_bytes([sa[2], sa[3]]);
        ev.addr = addr;
        ev.addrlen = addrlen;
        entry.submit(0);
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";