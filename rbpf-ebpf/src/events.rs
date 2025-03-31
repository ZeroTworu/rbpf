use crate::ip::ParseResult;
use aya_ebpf::{macros::map, maps::HashMap};
use network_types::ip::IpProto;

pub const DEBUG: u8 = 0;
pub const INFO: u8 = 1;
pub const WARN: u8 = 2;

#[map]
static mut EVENTS: HashMap<u32, LogMessage> = HashMap::with_max_entries(1, 0);

#[derive(Copy, Clone)]
#[repr(C)]
pub struct LogMessage {
    pub message: [u8; 128],

    pub input: bool,
    pub output: bool,
    pub v4: bool,
    pub v6: bool,
    pub tcp: bool,
    pub udp: bool,

    pub source_addr_v6: u128,
    pub destination_addr_v6: u128,

    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub rule_id: u32,
    pub ifindex: u32,

    pub source_port: u16,
    pub destination_port: u16,

    pub level: u8,
}

impl LogMessage {
    pub fn send_from_rule(message: &str, rule_id: u32, pac: &ParseResult, level: u8) -> Self {
        let msg = Self {
            message: Self::str_to_u8(message),
            rule_id,
            level,
            v4: true,
            v6: false,
            input: pac.input,
            output: pac.output,
            udp: pac.proto == IpProto::Udp,
            tcp: pac.proto == IpProto::Tcp,
            destination_addr_v4: pac.destination_addr_v4,
            source_addr_v4: pac.source_addr_v4,
            source_port: pac.source_port,
            destination_port: pac.destination_port,
            destination_addr_v6: pac.destination_addr_v6,
            source_addr_v6: pac.destination_addr_v6,
            ifindex: pac.ifindex,
        };
        send_log(&msg);
        msg
    }

    pub fn send_from(message: &str, pac: &ParseResult, level: u8) -> Self {
        let msg = Self {
            message: Self::str_to_u8(message),
            rule_id: 0,
            level,
            v4: true,
            v6: false,
            input: pac.input,
            output: pac.output,
            udp: pac.proto == IpProto::Udp,
            tcp: pac.proto == IpProto::Tcp,
            destination_addr_v4: pac.destination_addr_v4,
            source_addr_v4: pac.source_addr_v4,
            source_port: pac.source_port,
            destination_port: pac.destination_port,
            destination_addr_v6: pac.destination_addr_v6,
            source_addr_v6: pac.destination_addr_v6,
            ifindex: pac.ifindex,
        };
        send_log(&msg);
        msg
    }

    fn str_to_u8(msg: &str) -> [u8; 128] {
        let mut message = [0u8; 128];
        message[..msg.len()].copy_from_slice(msg.as_bytes());
        message
    }
}

pub fn send_log(msg: &LogMessage) -> i32 {
    let i: &u32 = &0;
    unsafe {
        if EVENTS.insert(i, msg, 0).is_err() {
            return 1;
        }
    }
    0
}
