#![no_std]


// Костыль что бы не заморачиваться с передачей enum eBPF -> userspace
pub const DEBUG: u8 = 0;
pub const INFO: u8 = 1;
pub const WARN: u8 = 2;
pub const ERROR: u8 = 3;
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Rule {
    pub drop: bool,
    pub ok: bool,
    pub v4: bool,
    pub v6: bool,
    pub tcp: bool,
    pub udp: bool,
    pub on: bool,

    pub source_addr_v6: u128,
    pub destination_addr_v6: u128,

    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub rule_id: u32,
    pub ifindex: u32,

    pub source_port_start: u16,
    pub source_port_end: u16,
    pub destination_port_start: u16,
    pub destination_port_end: u16,

    pub input: bool,
    pub output: bool,

    pub source_mask_v4: u8,
    pub destination_mask_v4: u8,
    pub source_mask_v6: u8,
    pub destination_mask_v6: u8,
}

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
    extern crate alloc;
    use super::*;
    use alloc::string::String;
    use core::net::{Ipv4Addr, Ipv6Addr};
    use serde::{Deserialize, Serialize};

    unsafe impl aya::Pod for LogMessage {}
    unsafe impl aya::Pod for Rule {}

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Control {
        pub action: ControlAction,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ControlAction {
        Reload = 0,
        GetRules = 1,
        UpdateRule = 2,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum TrafficType {
        Input = 0,
        Output = 1,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ActionType {
        Ok = 0,
        Drop = 1,
        Pipe = 2,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ProtocolVersionType {
        V4 = 0,
        V6 = 1,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ProtocolType {
        TCP = 0,
        UDP = 1,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct LogMessageSerialized {
        pub traffic_type: TrafficType,
        pub protocol_version_type: ProtocolVersionType,
        pub protocol_type: ProtocolType,

        pub source_addr_v6: Ipv6Addr,
        pub destination_addr_v6: Ipv6Addr,

        pub source_addr_v4: Ipv4Addr,
        pub destination_addr_v4: Ipv4Addr,
        pub rule_id: u32,
        pub if_name: String,
        pub rule_name: String,

        pub source_port: u16,
        pub destination_port: u16,

        pub level: u8,
        pub action: ActionType,
    }

}
