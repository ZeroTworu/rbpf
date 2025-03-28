use crate::filter::v6::{is_in_v6_block, is_out_v6_block};
use crate::ip::{ptr_at, TcContext};
use aya_ebpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_log_ebpf::{debug, warn};
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
}

pub fn parse_v6(ctx: &TcContext) -> Result<ParseResultV6, ()> {
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
    })
}

pub fn handle_ingress_v6(ctx: &TcContext) -> Result<i32, ()> {
    let ret = match parse_v6(&ctx) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    if is_in_v6_block(&ret) {
        warn!(
            ctx,
            "V6 [BLOCK] {:i}:{} as INPUT RULE", ret.source_addr, ret.source_port
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(
        ctx,
        "V6 INPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    Ok(TC_ACT_PIPE)
}

pub fn handle_egress_v6(ctx: &TcContext) -> Result<i32, ()> {
    let ret = match parse_v6(&ctx) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    if is_out_v6_block(&ret) {
        warn!(
            ctx,
            "V6 [BLOCK] {:i}:{} as OUTPUT RULE", ret.source_addr, ret.source_port
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(
        ctx,
        "V6 OUTPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    Ok(TC_ACT_PIPE)
}
