use sentinel_common::{OpenatEvent, ExecEvent, ConnectEvent};

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub fn openat_tracing(item: &[u8]){
    if item.len() < core::mem::size_of::<OpenatEvent>() {
        return;
    }
    let ev: OpenatEvent =
    unsafe { core::ptr::read_unaligned(item.as_ptr() as *const OpenatEvent) };
    println!(
        "openAt pid={} dfd={} flags={} mode={} file={}",
        ev.pid,
        ev.dfd,
        ev.flags,
        ev.mode,
        cstr(&ev.filename)
    );

}
pub fn execve_tracing(item: &[u8]){
    if item.len() < core::mem::size_of::<ExecEvent>() {
        return;
    }
    let ev: ExecEvent =
    unsafe { core::ptr::read_unaligned(item.as_ptr() as *const ExecEvent) };
    println!(
        "exec pid={} uid={} com={} file={}",
        ev.pid,
        ev.uid,
        cstr(&ev.comm),
        cstr(&ev.filename)
    );
}

pub fn connect_tracing(item: &[u8]){
    if item.len() < core::mem::size_of::<ConnectEvent>() {
        return;
    }
    let ev: ConnectEvent =
    unsafe { core::ptr::read_unaligned(item.as_ptr() as *const ConnectEvent) };
    let mut addr = format!("{}.{}.{}.{}.{}",  ev.addr[0], ev.addr[1], ev.addr[2], ev.addr[3], u16::from_be(ev.port));
    if ev.family == 10{
        addr = std::net::Ipv6Addr::from(ev.addr).to_string();
    }
    println!(
        "connect pid={} uid={} fd={} comm={} port={} address={} addresslen={}",
        ev.pid,
        ev.uid,
        ev.fd,
        cstr(&ev.comm),
        ev.port,
        addr,
        ev.addrlen
    );
}