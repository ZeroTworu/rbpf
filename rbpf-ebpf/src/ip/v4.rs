use crate::events;
use crate::events::LogMessage;
use crate::ip::{ptr_at, ptr_at_xdp, TcContext};
use crate::rules::{check_rule_v4, Action};
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::{debug, info, warn};
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

pub struct ParseResultV4 {
    pub source_port: u16,
    pub destination_port: u16,

    pub destination_addr: u32,
    pub source_addr: u32,

    pub proto: IpProto,

    pub input: bool,
    pub output: bool,
}

pub fn parse_v4_tc(ctx: &TcContext, input: bool) -> Result<ParseResultV4, ()> {
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let destination_addr = u32::from_be(ipv4hdr.dst_addr);
    let source_addr = u32::from_be(ipv4hdr.src_addr);
    let proto = ipv4hdr.proto;

    let (source_port, destination_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = unsafe { *ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = unsafe { *ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            (u16::from_be(udphdr.source), u16::from_be(udphdr.dest))
        }
        _ => return Err(()),
    };

    Ok(ParseResultV4 {
        source_port,
        destination_port,
        source_addr,
        destination_addr,
        proto,
        input,
        output: !input,
    })
}

pub fn parse_v4_xdp(ctx: &XdpContext, input: bool) -> Result<ParseResultV4, ()> {
    let ipv4hdr: Ipv4Hdr = unsafe { *ptr_at_xdp(&ctx, EthHdr::LEN)? };
    let destination_addr = u32::from_be(ipv4hdr.dst_addr);
    let source_addr = u32::from_be(ipv4hdr.src_addr);
    let proto = ipv4hdr.proto;
    let (source_port, destination_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = unsafe { *ptr_at_xdp(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = unsafe { *ptr_at_xdp(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            (u16::from_be(udphdr.source), u16::from_be(udphdr.dest))
        }
        _ => return Err(()),
    };

    Ok(ParseResultV4 {
        source_port,
        destination_port,
        source_addr,
        destination_addr,
        proto,
        input,
        output: !input,
    })
}

pub fn handle_ingress_v4(ctx: &XdpContext) -> Result<u32, ()> {
    let ret = match parse_v4_xdp(&ctx, true) {
        Ok(ret) => ret,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    debug!(
        ctx,
        "INPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    let (action, rule_id) = check_rule_v4(&ret);
    match action {
        Action::Ok => Ok(xdp_action::XDP_PASS),
        Action::Drop => {
            LogMessage::send_from_rule_v4("BAN", rule_id, &ret, events::WARN);
            Ok(xdp_action::XDP_DROP)
        }
        Action::Pipe => Ok(xdp_action::XDP_PASS),
    }
}

pub fn handle_egress_v4(ctx: &TcContext) -> Result<i32, ()> {
    let ret = match parse_v4_tc(&ctx, false) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };
    debug!(
        ctx,
        "OUTPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    let (action, rule_id) = check_rule_v4(&ret);
    match action {
        Action::Ok => Ok(TC_ACT_PIPE),
        Action::Drop => {
            LogMessage::send_from_rule_v4("BAN", rule_id, &ret, events::WARN);
            Ok(TC_ACT_SHOT)
        }
        Action::Pipe => Ok(TC_ACT_PIPE),
    }
}
