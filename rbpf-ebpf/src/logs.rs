use crate::ip::{UnhandledProtocolError, parser_result::ParseResult};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;
use core::ptr::addr_of_mut;
use network_types::ip::IpProto;
use rbpf_common::logs::{ERROR, LogMessage};

#[map]
static mut LOGS_RING_BUF: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

#[inline(always)]
pub fn now_ns() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

pub fn send_from_rule(message: &str, rule_id: u32, pac: &ParseResult, level: u8) {
    let src_ip_high: u64 = (pac.source_addr_v6 >> 64) as u64;
    let src_ip_low: u64 = pac.source_addr_v6 as u64;

    let dst_ip_high: u64 = (pac.destination_addr_v6 >> 64) as u64;
    let dst_ip_low: u64 = pac.destination_addr_v6 as u64;

    let msg = LogMessage {
        message: str_to_u8(message),
        rule_id,
        level,
        v4: pac.v4,
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
        unhandled_protocol: 255,
        timestamp: now_ns(),
    };
    send_log(msg);
}

pub fn send_from(message: &str, level: u8) {
    let msg = LogMessage {
        message: str_to_u8(message),
        rule_id: 0,
        level,
        v4: false,
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
        unhandled_protocol: 255,
        timestamp: now_ns(),
    };
    send_log(msg);
}

pub fn send_err_unhandled_protocol(message: &str, err: UnhandledProtocolError) {
    let src_ip_high: u64 = (err.src_v6 >> 64) as u64;
    let src_ip_low: u64 = err.src_v6 as u64;

    let dst_ip_high: u64 = (err.dst_v6 >> 64) as u64;
    let dst_ip_low: u64 = err.dst_v6 as u64;
    let msg = LogMessage {
        message: str_to_u8(message),
        rule_id: 0,
        level: ERROR,
        v4: err.v4,
        input: err.input,
        output: !err.input,
        udp: false,
        tcp: false,
        destination_addr_v4: err.dst_v4,
        source_addr_v4: err.src_v4,
        source_port: 0,
        destination_port: 0,
        src_ip_high,
        src_ip_low,
        dst_ip_high,
        dst_ip_low,
        ifindex: err.ifindex,
        unhandled_protocol: err.proto_as_u8(),
        timestamp: now_ns(),
    };

    send_log(msg);
}

fn str_to_u8(msg: &str) -> [u8; 128] {
    let mut message = [0u8; 128];
    message[..msg.len()].copy_from_slice(msg.as_bytes());
    message
}

pub fn send_log(msg: LogMessage) {
    unsafe {
        let ring_buf = addr_of_mut!(LOGS_RING_BUF);
        if let Some(mut buf) = (*ring_buf).reserve::<LogMessage>(0) {
            buf.write(msg);
            buf.submit(0);
        }
    }
}
