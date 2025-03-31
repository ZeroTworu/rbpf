#![no_std]

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct LogMessage {
    pub message: [u8; 128],
    pub input: bool,
    pub output: bool,
    pub v4: bool,
    pub v6: bool,
    pub tcp: bool,
    pub udp: bool,

    pub src_ip_high: u64,
    pub src_ip_low: u64,
    pub dst_ip_high: u64,
    pub dst_ip_low: u64,

    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub rule_id: u32,
    pub ifindex: u32,

    pub source_port: u16,
    pub destination_port: u16,

    pub level: u8,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for LogMessage {}
}
