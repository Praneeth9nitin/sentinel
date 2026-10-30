#![no_std]


pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent{
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; COMM_LEN],
    pub filename: [u8; PATH_LEN]
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}