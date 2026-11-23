use sentinel_common::{OpenatEvent, ExecEvent, ConnectEvent};
use crate::policy::{Policy, Verdict};
use std::net::{IpAddr, SocketAddr};

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub fn openat_tracing(item: &[u8], policy: &Policy) -> Option<(String, Verdict)>{
    if item.len() < core::mem::size_of::<OpenatEvent>() {
        return None;
    }
    let ev: OpenatEvent =
    unsafe { core::ptr::read_unaligned(item.as_ptr() as *const OpenatEvent) };
    let file = cstr(&ev.filename);
    let line = format!("openAt pid={} flags={} file={}", ev.pid, ev.flags, file);
    Some((line, policy.check_file(&file)))
}
pub fn execve_tracing(item: &[u8], policy: &Policy)->Option<(String, Verdict)>{
    if item.len() < core::mem::size_of::<ExecEvent>() {
        return None;
    }
    let ev: ExecEvent =
    unsafe { core::ptr::read_unaligned(item.as_ptr() as *const ExecEvent) };
    let file = cstr(&ev.filename);
    let line = format!("exec pid={} uid={} file={}", ev.pid, ev.uid, file);
    Some((line, policy.check_program(&file)))
}

pub fn connect_tracing(item: &[u8], policy: &Policy)->Option<(String, Verdict)>{
    if item.len() < core::mem::size_of::<ConnectEvent>() {
        return None;
    }
    let ev: ConnectEvent =
    unsafe { core::ptr::read_unaligned(item.as_ptr() as *const ConnectEvent) };
    let port = u16::from_be(ev.port);
    let ip = match ev.family {
        2 => IpAddr::from([ev.addr[0], ev.addr[1], ev.addr[2], ev.addr[3]]),
        10 => IpAddr::from(ev.addr),
        _ => return None,
    };
    let line = format!(
        "connect pid={} comm={} dst={}",
        ev.pid,
        cstr(&ev.comm),
        SocketAddr::new(ip, port)
    );
    Some((line, policy.check_connect(ip, port)))
}