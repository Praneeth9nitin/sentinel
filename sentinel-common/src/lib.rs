#![no_std]


pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent{
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; COMM_LEN],
    pub filename: [u8; PATH_LEN]
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenatEvent{
    pub kind: u32,
    pub pid: u32,
    pub dfd: i32,
    pub flags: u32,
    pub mode: u32,
    pub filename: [u8; PATH_LEN]
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub fd: i32,
    pub comm: [u8; COMM_LEN],   // 16
    pub family: u16,            // 2 = IPv4, 10 = IPv6
    pub port: u16,              // network byte order, convert in userspace
    pub addr: [u8; 16],         // IPv4 uses the first 4 bytes
    pub addrlen: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OpenatEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectEvent {}