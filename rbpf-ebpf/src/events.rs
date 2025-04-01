use crate::ip::ParseResult;
use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;
use core::hash::Hasher;
use network_types::ip::IpProto;
use rbpf_common::LogMessage;

pub const DEBUG: u8 = 0;
pub const INFO: u8 = 1;
pub const WARN: u8 = 2;
#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

#[derive(Copy, Clone)]
#[repr(C)]
pub struct WLogMessage {
    pub msg: LogMessage,
}

impl WLogMessage {
    pub fn send_from_rule(message: &str, rule_id: u32, pac: &ParseResult, level: u8) -> Self {
        let src_ip_high: u64 = (pac.source_addr_v6 >> 64) as u64;
        let src_ip_low: u64 = pac.source_addr_v6 as u64;

        let dst_ip_high: u64 = (pac.destination_addr_v6 >> 64) as u64;
        let dst_ip_low: u64 = pac.destination_addr_v6 as u64;

        let msg = Self {
            msg: LogMessage {
                message: Self::str_to_u8(message),
                rule_id,
                level,
                v4: pac.v4,
                v6: pac.v6,
                input: pac.input,
                output: pac.output,
                udp: pac.proto == IpProto::Udp,
                tcp: pac.proto == IpProto::Tcp,
                destination_addr_v4: pac.destination_addr_v4,
                source_addr_v4: pac.source_addr_v4,
                source_port: pac.source_port,
                destination_port: pac.destination_port,
                src_ip_high,
                src_ip_low,
                dst_ip_high,
                dst_ip_low,
                ifindex: pac.ifindex,
            },
        };
        send_log(msg.msg);
        msg
    }

    pub fn send_from(message: &str, level: u8) -> Self {
        let msg = Self {
            msg: LogMessage {
                message: Self::str_to_u8(message),
                rule_id: 0,
                level,
                v4: false,
                v6: false,
                input: false,
                output: false,
                udp: false,
                tcp: false,
                destination_addr_v4: 0,
                source_addr_v4: 0,
                source_port: 0,
                destination_port: 0,
                src_ip_high: 0,
                src_ip_low: 0,
                dst_ip_high: 0,
                dst_ip_low: 0,
                ifindex: 0,
            },
        };
        send_log(msg.msg);
        msg
    }

    fn str_to_u8(msg: &str) -> [u8; 128] {
        let mut message = [0u8; 128];
        message[..msg.len()].copy_from_slice(msg.as_bytes());
        message
    }
}

pub fn send_log(msg: LogMessage) {
    unsafe {
        if let Some(mut buf) = EVENTS.reserve::<LogMessage>(0) {
            buf.write(msg);
            buf.submit(0);
        }
    }
}
