use crate::events::LogMessage;
use crate::ip::{ptr_at, ptr_at_xdp, TcContext};
use crate::rules::v6;
use crate::{events, rules};
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::debug;
use core::net::Ipv6Addr;
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

pub struct ParseResultV6 {
    pub source_port: u16,
    pub destination_port: u16,

    pub destination_addr: Ipv6Addr,
    pub source_addr: Ipv6Addr,

    pub proto: IpProto,

    pub input: bool,
    pub output: bool,
}

pub fn parse_v6(ctx: &TcContext, input: bool) -> Result<ParseResultV6, ()> {
    let ipv6hdr: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

    let destination_addr = Ipv6Addr::from(unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 });

    let source_addr = Ipv6Addr::from(unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 });

    let proto = ipv6hdr.next_hdr;

    let (source_port, destination_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = unsafe { *ptr_at(ctx, EthHdr::LEN + Ipv6Hdr::LEN)? };
            (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = unsafe { *ptr_at(ctx, EthHdr::LEN + Ipv6Hdr::LEN)? };
            (u16::from_be(udphdr.source), u16::from_be(udphdr.dest))
        }
        _ => return Err(()),
    };
    Ok(ParseResultV6 {
        source_port,
        destination_port,
        source_addr,
        destination_addr,
        proto,
        input,
        output: !input,
    })
}

pub fn parse_v6_xdp(ctx: &XdpContext, input: bool) -> Result<ParseResultV6, ()> {
    let ipv6hdr: Ipv6Hdr = unsafe { *ptr_at_xdp(&ctx, EthHdr::LEN)? };
    let destination_addr = Ipv6Addr::from(unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 });
    let source_addr = Ipv6Addr::from(unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 });
    let proto = ipv6hdr.next_hdr;
    let (source_port, destination_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = unsafe { *ptr_at_xdp(ctx, EthHdr::LEN + Ipv6Hdr::LEN)? };
            (u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest))
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = unsafe { *ptr_at_xdp(ctx, EthHdr::LEN + Ipv6Hdr::LEN)? };
            (u16::from_be(udphdr.source), u16::from_be(udphdr.dest))
        }
        _ => return Err(()),
    };
    Ok(ParseResultV6 {
        source_port,
        destination_port,
        source_addr,
        destination_addr,
        proto,
        input,
        output: !input,
    })
}

pub fn handle_ingress_v6(ctx: &XdpContext) -> Result<u32, ()> {
    let ret = match parse_v6_xdp(&ctx, true) {
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

    let (action, rule_id) = v6::check_rule_v6(&ret);
    match action {
        rules::Action::Ok => Ok(xdp_action::XDP_PASS),
        rules::Action::Drop => {
            LogMessage::send_from_rule_v6("BAN", rule_id, &ret, events::WARN);
            Ok(xdp_action::XDP_DROP)
        }
        rules::Action::Pipe => Ok(xdp_action::XDP_PASS),
    }
}

pub fn handle_egress_v6(ctx: &TcContext) -> Result<i32, ()> {
    let ret = match parse_v6(&ctx, false) {
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

    let (action, rule_id) = v6::check_rule_v6(&ret);
    match action {
        rules::Action::Ok => Ok(TC_ACT_PIPE),
        rules::Action::Drop => {
            LogMessage::send_from_rule_v6("BAN", rule_id, &ret, events::WARN);
            Ok(TC_ACT_SHOT)
        }
        rules::Action::Pipe => Ok(TC_ACT_PIPE),
    }
}
