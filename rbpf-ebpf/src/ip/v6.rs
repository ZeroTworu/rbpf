use crate::filter::v6::{
    is_in_v6_block, is_in_v6_subnet_block, is_out_v6_block, is_out_v6_subnet_block,
};
use crate::ip::{ptr_at, ptr_at_xdp, TcContext};
use aya_ebpf::bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::programs::XdpContext;
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

pub fn parse_v6_xdp(ctx: &XdpContext) -> Result<ParseResultV6, ()> {
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
    })
}

pub fn handle_ingress_v6(ctx: &XdpContext) -> Result<u32, ()> {
    let ret = match parse_v6_xdp(&ctx) {
        Ok(ret) => ret,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    if is_in_v6_block(&ret) {
        warn!(
            ctx,
            "[BLOCK] {:i}:{} as INPUT RULE", ret.source_addr, ret.source_port
        );
        return Ok(xdp_action::XDP_DROP);
    }

    if is_in_v6_subnet_block(&ret) {
        warn!(
            ctx,
            "[BLOCK] {:i}:{} as INPUT RULE (SUBNET)", ret.source_addr, ret.source_port
        );
        return Ok(xdp_action::XDP_DROP);
    }

    debug!(
        ctx,
        "INPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    Ok(xdp_action::XDP_PASS)
}

pub fn handle_egress_v6(ctx: &TcContext) -> Result<i32, ()> {
    let ret = match parse_v6(&ctx) {
        Ok(ret) => ret,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    if is_out_v6_block(&ret) {
        warn!(
            ctx,
            "[BLOCK] {:i}:{} as OUTPUT RULE", ret.source_addr, ret.source_port
        );
        return Ok(TC_ACT_SHOT);
    }

    if is_out_v6_subnet_block(&ret) {
        warn!(
            ctx,
            "[BLOCK] {:i}:{} as OUTPUT RULE (SUBNET)", ret.source_addr, ret.source_port
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(
        ctx,
        "OUTPUT: {:i}:{} -> {:i}:{}",
        ret.source_addr,
        ret.source_port,
        ret.destination_addr,
        ret.destination_port
    );

    Ok(TC_ACT_PIPE)
}
