#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use sentinel_common::ExecEvent;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn sentinel(ctx: TracePointContext) -> u32 {
    match try_execve(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let filename_ptr = unsafe { ctx.read_at::<u64>(16)? } as *const u8;

    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        let ev = unsafe { &mut *entry.as_mut_ptr() };
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";